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
                List<String> opsFromDb = fctFromDb.getOps();
                List<String> a = new ArrayList<String>();
                List<String> b = new ArrayList<String>();

                if (opsFromDb.size() < ops.size()) {
                    a = opsFromDb;
                    b = ops;
                } else {
                    a = ops;
                    b = opsFromDb;
                }
                int i = 0;
                int j = 0;
                Float result = 0.0f;
                float count = 0;

                for (; i < a.size(); i++) {
                    j = i;
                    if (a.get(i).equals(b.get(j))) {
                        count++;
                    } else {
                        while (true) {

                            j++;
                            if (j >= b.size()) {
                                j = i;
                                break;
                            } else if (a.get(i).equals(b.get(j))) {
                                count += 1.0f / ((j - i) * (j - i));
                                break;
                            }
                        }
                    }
                }

                result = ((float) count / a.size());

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