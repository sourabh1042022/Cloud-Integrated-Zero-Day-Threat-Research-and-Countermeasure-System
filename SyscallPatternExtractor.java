import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class SyscallPatternExtractor extends GhidraScript {

    @Override
    public void run() throws Exception {
        Listing listing = currentProgram.getListing();
        FunctionIterator functions = listing.getFunctions(true);
        List<String> results = new ArrayList<>();

        while (functions.hasNext()) {
            Function function = functions.next();
            InstructionIterator instructions = listing.getInstructions(function.getBody(), true);

            while (instructions.hasNext()) {
                Instruction instr = instructions.next();
                if (instr.getMnemonicString().equalsIgnoreCase("syscall")) {
                    Address addr = instr.getAddress();
                    results.add("Syscall at: " + addr.toString() + " in function " + function.getName());
                }
            }
        }

        try (PrintWriter out = new PrintWriter(new FileWriter("sample_extracted_syscalls.json"))) {
            out.println("{");
            out.println("\"extracted_syscalls\": [");
            for (int i = 0; i < results.size(); i++) {
                out.print("  \"" + results.get(i) + "\"");
                if (i != results.size() - 1) out.println(",");
                else out.println();
            }
            out.println("]");
            out.println("}");
        }

        println("Syscall extraction complete.");
    }
}
