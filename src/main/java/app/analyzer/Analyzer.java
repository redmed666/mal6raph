package app.analyzer;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.radare.r2pipe.R2Pipe;

import app.sample.Function;
import app.sample.Sample;

public class Analyzer {

    public Sample analyzeSample(String filepath, JsonObject config) throws Exception {
        Sample sample = new Sample();

        JsonParser jsonParser = new JsonParser();
        R2Pipe r2p = new R2Pipe(filepath);
        r2p.cmd("aac");

        JsonObject allInfo = jsonParser.parse(r2p.cmd("iaj")).getAsJsonObject();
        JsonObject info = allInfo.get("info").getAsJsonObject();
        JsonObject sampleStrings = jsonParser.parse(r2p.cmd("izzj")).getAsJsonObject();

        HashSet<String> strings = new HashSet<String>();

        for (JsonElement eString : sampleStrings.get("strings").getAsJsonArray()) {
            String string = "\"" + eString.getAsJsonObject().get("string").getAsString() + "\"";
            if (string.length() > config.get("THRESHOLD_STR_SIZE").getAsInt()) {
                strings.add(string);
            }
        }

        sample.setStrings(strings);

        sample.setArch(info.get("arch").getAsString());
        sample.setBits(info.get("bits").getAsInt());
        sample.setImports(allInfo.get("imports").getAsJsonArray());
        sample.setExports(allInfo.get("exports").getAsJsonArray());

        JsonArray functionsInfo = jsonParser.parse(r2p.cmd("aflj")).getAsJsonArray();

        List<Function> functions = Collections.synchronizedList(new ArrayList<Function>());
        List<String> sha256Fns = new ArrayList<String>();
        ConcurrentLinkedQueue<JsonObject> queue = new ConcurrentLinkedQueue<JsonObject>();

        for (JsonElement eFunctionInfo : functionsInfo) {
            JsonObject functionInfo = eFunctionInfo.getAsJsonObject();
            queue.add(functionInfo);
        }

        List<Thread> threads = new ArrayList<Thread>();
        for (Integer i = 0; i < config.get("NUMBER_THREADS").getAsInt(); ++i) {
            AnalyzeFunctionThread runnable = new AnalyzeFunctionThread(queue, filepath, config, sha256Fns, functions);
            Thread thread = new Thread(runnable);
            thread.start();
            threads.add(thread);
        }

        for (Thread thread : threads) {
            thread.join();
        }

        sample.setFunctions(functions);
        r2p.quit();
        return sample;
    }

    public void analyzeSimil(Function source, List<Function> fromDb, List<Map<String, Float>> similarities,
            JsonObject config) throws Exception {
        String sha256Max = "";

        ConcurrentLinkedQueue<Function> queue = new ConcurrentLinkedQueue<Function>();

        for (Function function : fromDb) {
            queue.add(function);
        }

        List<Thread> threads = new ArrayList<Thread>();
        for (int i = 0; i < config.get("NUMBER_THREADS").getAsInt(); i++) {
            AnalyzeFunctionSimilThread runnable = new AnalyzeFunctionSimilThread(queue, source, similarities,
                    config.get("THRESHOLD_SIMILARITY").getAsFloat());
            Thread thread = new Thread(runnable);
            thread.start();
            threads.add(thread);
        }

        for (Thread thread : threads) {
            thread.join();
        }
    }
}