package com.platypus.proxy.asm;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import org.objectweb.asm.*;
import org.objectweb.asm.tree.*;

/**
 * Utilizes the ASM Tree API.
 * <p>
 * Features:
 * <ul>
 *   <li>No bytecode offset counting - the tree contains line number nodes directly.</li>
 *   <li>Local variables for argument storage are allocated from {@code methodNode.maxLocals},
 *       then {@code maxLocals} is updated. {@code COMPUTE_FRAMES} handles the rest.</li>
 *   <li>Line numbers are found by scanning backwards from the call instruction until a
 *       {@link LineNumberNode} is found.</li>
 *   <li>Argument injection uses {@link InsnList} insertions rather than manual
 *       {@code visitInsn} sequences.</li>
 * </ul>
 */
public class LogCallRewriter {

    private static final String LOGGER_CLASS = "com/platypus/proxy/logging/CondLogger";
    private static final String OLD_DESCRIPTOR = "(Ljava/lang/String;[Ljava/lang/Object;)V";
    private static final String NEW_METHOD = "log";
    private static final String NEW_DESCRIPTOR =
            "(Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;[Ljava/lang/Object;)V";

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.err.println("Usage: java LogCallRewriter <output-directory>");
            System.exit(1);
        }
        Path outputDir = Paths.get(args[0]);
        if (!Files.isDirectory(outputDir)) {
            System.err.println("Not a directory: " + outputDir);
            System.exit(1);
        }
        Files.walkFileTree(outputDir, new SimpleFileVisitor<Path>() {
            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) throws IOException {
                if (file.toString().endsWith(".class")) {
                    transformClass(file);
                }
                return FileVisitResult.CONTINUE;
            }
        });
    }

    /**
     * Creates the optimal integer push instruction node (ICONST_*, BIPUSH, SIPUSH or LDC).
     */
    private static AbstractInsnNode createIntInsn(int value) {
        if (value >= -1 && value <= 5) {
            return new InsnNode(Opcodes.ICONST_0 + value);
        } else if (value >= Byte.MIN_VALUE && value <= Byte.MAX_VALUE) {
            return new IntInsnNode(Opcodes.BIPUSH, value);
        } else if (value >= Short.MIN_VALUE && value <= Short.MAX_VALUE) {
            return new IntInsnNode(Opcodes.SIPUSH, value);
        } else {
            return new LdcInsnNode(value);
        }
    }

    private static void transformClass(Path classFile) {
        try {
            byte[] bytes = Files.readAllBytes(classFile);

            // 1. Read the class into a ClassNode
            ClassReader cr = new ClassReader(bytes);
            ClassNode classNode = new ClassNode(Opcodes.ASM9);
            cr.accept(classNode, 0);

            // 2. Transform every method
            boolean anyChange = false;
            String simpleClassName = classNode.name.substring(classNode.name.lastIndexOf('/') + 1);

            for (MethodNode method : classNode.methods) {
                // Collect all matching call instructions first
                List<MethodInsnNode> callsToReplace = new ArrayList<>();
                for (AbstractInsnNode insn : method.instructions.toArray()) {
                    if (insn instanceof MethodInsnNode) {
                        MethodInsnNode call = (MethodInsnNode) insn;
                        if (isTargetCall(call)) {
                            callsToReplace.add(call);
                        }
                    }
                }

                if (callsToReplace.isEmpty()) {
                    continue;
                }

                anyChange = true;

                // Allocate fresh local variables from the method's max locals
                int maxLocals = method.maxLocals;
                int stringLocal = maxLocals++;
                int objectsLocal = maxLocals++;
                method.maxLocals = maxLocals; // Update so COMPUTE_FRAMES knows about them

                for (MethodInsnNode call : callsToReplace) {
                    String level = call.name.toUpperCase();

                    // Find the closest preceding line number
                    int line = -1;
                    AbstractInsnNode current = call.getPrevious();
                    while (current != null) {
                        if (current instanceof LineNumberNode) {
                            line = ((LineNumberNode) current).line;
                            break;
                        }
                        current = current.getPrevious();
                    }

                    // Determine the opcode for the new call (preserve static/instance nature)
                    int newOpcode =
                            (call.getOpcode() == Opcodes.INVOKESTATIC) ? Opcodes.INVOKESTATIC : call.getOpcode();

                    // Build the replacement instruction list
                    InsnList replacement = new InsnList();
                    // 1. Store the original two arguments into locals
                    replacement.add(new VarInsnNode(Opcodes.ASTORE, objectsLocal)); // pop Object[]
                    replacement.add(new VarInsnNode(Opcodes.ASTORE, stringLocal)); // pop String
                    // 2. Push the new arguments
                    replacement.add(new LdcInsnNode(level));
                    replacement.add(new LdcInsnNode(simpleClassName));
                    replacement.add(createIntInsn(line));
                    // 3. Restore the original arguments
                    replacement.add(new VarInsnNode(Opcodes.ALOAD, stringLocal));
                    replacement.add(new VarInsnNode(Opcodes.ALOAD, objectsLocal));
                    // 4. Call the unified log method
                    replacement.add(new MethodInsnNode(newOpcode, LOGGER_CLASS, NEW_METHOD, NEW_DESCRIPTOR, false));

                    // Insert the new sequence right before the old call, then remove the old call
                    method.instructions.insert(call, replacement);
                    method.instructions.remove(call);
                }
            }

            // 3. Write the transformed class
            if (anyChange) {
                ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);
                classNode.accept(cw);
                byte[] transformed = cw.toByteArray();
                Files.write(classFile, transformed);
                System.out.println("Transformed: " + classFile);
            }
        } catch (IOException e) {
            System.err.println("Failed to process " + classFile + ": " + e.getMessage());
        }
    }

    /**
     * Checks whether a {@link MethodInsnNode} is a target call:
     * static or instance call on CondLogger, with the old descriptor,
     * method name starting with an uppercase letter (indicating a log level).
     */
    private static boolean isTargetCall(MethodInsnNode call) {
        int opcode = call.getOpcode();
        boolean isStaticOrInstance = (opcode == Opcodes.INVOKESTATIC
                || opcode == Opcodes.INVOKEVIRTUAL
                || opcode == Opcodes.INVOKEINTERFACE);
        return isStaticOrInstance
                && call.owner.equals(LOGGER_CLASS)
                && call.desc.equals(OLD_DESCRIPTOR)
                && !call.name.isEmpty()
                && Character.isUpperCase(call.name.charAt(0));
    }
}
