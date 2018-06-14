package app.analyzer;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.radare.r2pipe.R2Pipe;

import app.sample.Function;

public class AnalyzeFunctionThread implements Runnable {
    Thread thread;
    private ConcurrentLinkedQueue<JsonObject> queue;
    private String filepath;
    private JsonObject config;
    private List<String> sha256Fns;
    private List<Function> functions;

    AnalyzeFunctionThread(ConcurrentLinkedQueue<JsonObject> queue, String filepath, JsonObject config,
            List<String> sha256Fns, List<Function> functions) {
        this.queue = queue;
        this.filepath = filepath;
        this.config = config;
        this.sha256Fns = sha256Fns;
        this.functions = functions;
    }

    public void run() {
        try {
            R2Pipe r2p = new R2Pipe(filepath);
            while (!queue.isEmpty()) {
                JsonObject functionInfo = queue.remove();
                Function function = new Function();
                JsonParser jsonParser = new JsonParser();

                if (functionInfo.get("size").getAsInt() >= config.get("THRESHOLD_FCT_SIZE").getAsInt()) {
                    Integer offset = functionInfo.get("offset").getAsInt();
                    function.setOffset(offset);
                    r2p.cmd(String.format("af @ %d", offset));
                    String sha256Fn = r2p.cmd(String.format("ph sha256 %d @ %d", functionInfo.get("size").getAsInt(),
                            functionInfo.get("offset").getAsInt())).toUpperCase().replace("\n", "");

                    if (!sha256Fns.contains(sha256Fn)) {
                        String md5Fn = r2p.cmd(String.format("ph md5 %d @ %d", functionInfo.get("size").getAsInt(),
                                functionInfo.get("offset").getAsInt())).toUpperCase().replace("\n", "");

                        function.setSha256(sha256Fn);
                        function.setMd5(md5Fn);
                        String resultPdfj = r2p.cmd(String.format("pdfj @ %d", offset));
                        JsonObject fnDisas = jsonParser.parse(resultPdfj).getAsJsonObject();

                        JsonArray ops = fnDisas.get("ops").getAsJsonArray();
                        List<String> fnOps = new ArrayList<String>();
                        for (JsonElement eOp : ops) {
                            JsonObject op = eOp.getAsJsonObject();
                            if (op.has("type")) {
                                String sOp = op.get("type").getAsString();
                                fnOps.add("\"" + sOp + "\"");
                            }
                        }
                        function.setOps(fnOps);
                        function.setSize(functionInfo.get("size").getAsLong());
                        function.setOffset(functionInfo.get("offset").getAsInt());
                        functions.add(function);
                    }
                }

            }
            r2p.quit();
        } catch (Exception e) {
            System.out.println("ANALYZEFCTTHREAD: " + e.getMessage());
        }
    }
}