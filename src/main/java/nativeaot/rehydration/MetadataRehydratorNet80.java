
package nativeaot.rehydration;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.ArrayList;

import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.MemoryByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import nativeaot.Constants;

public class MetadataRehydratorNet80 extends MetadataRehydrator {

    @Override
    public PointerScanResult rehydrate(Program program, AddressRange dehydrated, TaskMonitor monitor, MessageLog log) throws Exception {
        var memory = program.getMemory();
        var listing = program.getListing();
        var space = dehydrated.getAddressSpace();

        var reader = new BinaryReader(new MemoryByteProvider(memory, space), true);
        reader.setPointerIndex(dehydrated.getMinAddress().getOffset());

        var hydrationBase = readRelPtr32(space, reader);

        // Initialize with zero bytes.
        var block = memory.getBlock(hydrationBase);
        try {
            memory.convertToInitialized(block, (byte) 0x00);
        } catch (IllegalArgumentException ex) {
            // Memory block was already initialized. We can ignore this.
        }

        // Fixups table appears right after dehydrated data.
        var fixupsStart = dehydrated.getMaxAddress();
        
        monitor.setShowProgressValue(true);
        monitor.setIndeterminate(false);
        monitor.setProgress(0);
        monitor.setMaximum(dehydrated.getLength());
        monitor.setMessage(String.format("%s: Rehydrating .NET metadata...", Constants.TAG));

        // TODO: relocation registration.
        var pointerLocations = new ArrayList<Address>();

        try (var hydrated = new ByteArrayOutputStream()) {
            var command = new DehydratedDataCommand();
            while (reader.getPointerIndex() < dehydrated.getMaxAddress().getOffset()) {
                // Update progress.
                monitor.checkCancelled();
                monitor.setProgress(reader.getPointerIndex() - dehydrated.getMinAddress().getOffset());

                // Read next comment.
                long offset = reader.getPointerIndex();
                command.initFromReader(reader);

                if (markupRehydrationCode()) {
                    listing.setComment(space.getAddress(offset), CodeUnit.EOL_COMMENT, command.toString());
                }

                // Simulate next command.
                int payload = command.getPayload();
                switch (command.getCommand()) {
                    case DehydratedDataCommand.COPY -> {
                        hydrated.write(reader.readNextByteArray(payload));
                    }

                    case DehydratedDataCommand.ZERO_FILL -> {
                        for (int i = 0; i < payload; i++) {
                            hydrated.write(0);
                        }
                    }

                    case DehydratedDataCommand.REL_PTR32_RELOC -> {
                        var ptr = readRelPtr32(space, reader, fixupsStart.getOffset() + payload * 4);
                        writeRelPtr32(hydrated, ptr);
                    }

                    case DehydratedDataCommand.PTR_RELOC -> {
                        var ptr = readRelPtr32(space, reader, fixupsStart.getOffset() + payload * 4);
                        pointerLocations.add(hydrationBase.add(hydrated.size()));
                        writeInt64(hydrated, ptr.getOffset());
                    }

                    case DehydratedDataCommand.INLINE_REL_PTR32_RELOC -> {
                        for (int i = 0; i < payload; i++) {
                            monitor.checkCancelled();
                            writeRelPtr32(hydrated, readRelPtr32(space, reader));
                        }
                    }

                    case DehydratedDataCommand.INLINE_PTR_RELOC -> {
                        for (int i = 0; i < payload; i++) {
                            monitor.checkCancelled();
                            pointerLocations.add(hydrationBase.add(hydrated.size()));
                            writeInt64(hydrated, readRelPtr32(space, reader).getOffset());
                        }
                    }

                    default -> throw new Exception(String.format("%x: %s", reader.getPointerIndex(), command));
                }
            }

            memory.setBytes(hydrationBase, hydrated.toByteArray());
            monitor.setProgress(monitor.getMaximum());
            
            var finalRange = new AddressSet(hydrationBase, hydrationBase.add(hydrated.size())).getFirstRange();
            
            return new PointerScanResult(
                finalRange,
                pointerLocations.toArray(Address[]::new)
            );
        }
    }

    private static Address readRelPtr32(AddressSpace space, BinaryReader reader) throws IOException {
        long base = reader.getPointerIndex();
        int offset = reader.readNextInt();
        return space.getAddress(base + offset);
    }

    private static Address readRelPtr32(AddressSpace space, BinaryReader reader, long index) throws IOException {
        long base = index;
        int offset = reader.readInt(index);
        return space.getAddress(base + offset);
    }

    private static void writeRelPtr32(ByteArrayOutputStream output, Address ptr) throws IOException {
        int delta = (int) (ptr.getOffset() - output.size());
        writeInt32(output, delta);
    }

    private static void writeInt32(ByteArrayOutputStream output, int value) throws IOException {
        // No little-endian writer in ByteArrayOutputStream or DataOutputStream :(
        output.write(value & 0xFF);
        output.write((value >> 8) & 0xFF);
        output.write((value >> 16) & 0xFF);
        output.write((value >> 24) & 0xFF);
    }

    private static void writeInt64(ByteArrayOutputStream output, long value) throws IOException {
        // No little-endian writer in ByteArrayOutputStream or DataOutputStream :(
        output.write((int) (value & 0xFF));
        output.write((int) ((value >> 8) & 0xFF));
        output.write((int) ((value >> 16) & 0xFF));
        output.write((int) ((value >> 24) & 0xFF));
        output.write((int) ((value >> 32) & 0xFF));
        output.write((int) ((value >> 40) & 0xFF));
        output.write((int) ((value >> 48) & 0xFF));
        output.write((int) ((value >> 56) & 0xFF));
    }

    class DehydratedDataCommand {
        public static final byte COPY = 0x00;
        public static final byte ZERO_FILL = 0x01;
        public static final byte REL_PTR32_RELOC = 0x02;
        public static final byte PTR_RELOC = 0x03;
        public static final byte INLINE_REL_PTR32_RELOC = 0x04;
        public static final byte INLINE_PTR_RELOC = 0x05;

        private static final byte DEHYDRATED_DATA_COMMAND_MASK = 0x07;
        private static final int DEHYDRATED_DATA_COMMAND_PAYLOAD_SHIFT = 3;
        private static final int MAX_RAW_SHORT_PAYLOAD = (1 << (8 - DEHYDRATED_DATA_COMMAND_PAYLOAD_SHIFT)) - 1;
        private static final int MAX_EXTRA_PAYLOAD_BYTES = 3;
        private static final int MAX_SHORT_PAYLOAD = MAX_RAW_SHORT_PAYLOAD - MAX_EXTRA_PAYLOAD_BYTES;

        private byte _command;
        private int _payload;

        public DehydratedDataCommand() {
        }

        public DehydratedDataCommand(BinaryReader reader) throws Exception {
            initFromReader(reader);
        }

        public byte getCommand() {
            return _command;
        }

        public int getPayload() {
            return _payload;
        }

        public final void initFromReader(BinaryReader reader) throws IOException {
            int b = (int) reader.readNextByte() & 0xFF;
            _command = (byte) (b & DEHYDRATED_DATA_COMMAND_MASK);
            _payload = b >> DEHYDRATED_DATA_COMMAND_PAYLOAD_SHIFT;
            int extraBytes = _payload - MAX_SHORT_PAYLOAD;
            if (extraBytes > 0) {
                _payload = ((int) reader.readNextByte() & 0xFF);
                if (extraBytes > 1) {
                    _payload += (((int) reader.readNextByte() & 0xFF) << 8);
                    if (extraBytes > 2)
                        _payload += ((int) reader.readNextByte() & 0xFF) << 16;
                }

                _payload += MAX_SHORT_PAYLOAD;
            }
        }

        @Override
        public String toString() {
            return switch (getCommand()) {
                case DehydratedDataCommand.COPY -> String.format("COPY %x", getPayload());
                case DehydratedDataCommand.ZERO_FILL -> String.format("ZERO_FILL %x", getPayload());
                case DehydratedDataCommand.REL_PTR32_RELOC -> String.format("REL_PTR32_RELOC %x", getPayload());
                case DehydratedDataCommand.PTR_RELOC -> String.format("PTR_RELOC %x", getPayload());
                case DehydratedDataCommand.INLINE_REL_PTR32_RELOC -> String.format("INLINE_REL_PTR32_RELOC %x", getPayload());
                case DehydratedDataCommand.INLINE_PTR_RELOC -> String.format("INLINE_PTR_RELOC %x", getPayload());
                default -> "???";
            };
        }
    }
}