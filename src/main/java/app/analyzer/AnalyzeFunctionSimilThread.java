package app.analyzer;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedQueue;

import app.sample.Function;

public class AnalyzeFunctionSimilThread implements Runnable {
    Thread thread;
    private ConcurrentLinkedQueue<Function> queue;
    private Function function;
    private List<String> ops;
    private List<Map<String, Float>> similarities;
    private Float thresholdSimil;

    AnalyzeFunctionSimilThread(ConcurrentLinkedQueue<Function> queue, Function functionFromSample,
            List<Map<String, Float>> similarities, Float thresholdSimil) {
        this.queue = queue;
        this.function = functionFromSample;
        this.ops = functionFromSample.getOps();
        this.similarities = similarities;
        this.thresholdSimil = thresholdSimil;
    }

    public void run() {
        try {
            while (!queue.isEmpty()) {
                Function fctFromDb = queue.remove();
                List<Long> minHashes = function.getMinHashes();
                List<Long> minHashesDb = fctFromDb.getMinHashes();
                float result = 0.0f;

                for (int i = 0; i < minHashes.size(); i++) {
                    if (minHashes.get(i) == minHashesDb.get(i)) {
                        result += 1.0f;
                    }
                }

                result = result / minHashes.size();

                if (result > thresholdSimil) {
                    Map<String, Float> simil = new HashMap<String, Float>();
                    simil.put(fctFromDb.getSha256(), result);
                    similarities.add(simil);
                }
            }
        } catch (Exception e) {
            System.out.println("ANALYZESIMILFCT: " + e.getMessage());
        }
    }
}