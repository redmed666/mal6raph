package app.analyzer;

import java.util.ArrayList;
import java.util.Collections;
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
    private int[] randomNmbr = new int[199];

    AnalyzeFunctionThread(ConcurrentLinkedQueue<JsonObject> queue, String filepath, JsonObject config,
            List<String> sha256Fns, List<Function> functions) {
        this.queue = queue;
        this.filepath = filepath;
        this.config = config;
        this.sha256Fns = sha256Fns;
        this.functions = functions;
        this.randomNmbr = new int[] { 1989735305, 937652563, -858736237, -1314812694, 689251750, -82709320, 795312299,
                -544860971, 1643576404, 1430640549, 1452333766, -1536706600, 513790685, 626965802, -1591987495,
                -1005352102, 518564333, -831987165, -755555970, 1860608833, -129328750, 984952806, 821088494,
                1399126281, -1392401138, -1395491710, -1154810148, -1612065845, 1656072741, 1878965672, -1599756289,
                1186755924, -1410735329, 144841619, 1875667893, -1550303317, 954598499, 1135412800, -630755964,
                1513709726, -1928387401, -1820649880, -307362372, 1257767111, 778596038, -1183035204, 1031375411,
                2028753681, -1932700636, -1261303876, 1839271356, 152509909, -134452230, 1881059427, 1421305696,
                172291590, -1515776096, 2105730843, 1557623705, -2021291457, 1795672408, -1588044146, 1456802927,
                1769128820, 473701368, -655463627, 492886931, 1046738662, -828970335, 236158403, -173160749, 467318248,
                1502589225, -463658513, 745561586, 74159143, 591846481, -343358741, -683850407, -1000324578, 948991500,
                2084974641, 1852480401, 1263722865, 299067429, -1035600781, -628908195, -2076880021, 177854003,
                -339650490, 1587685288, -1245272820, 618658110, -1238004758, -100156118, 1635289, -871105202,
                -2016460952, 126610062, 668186554, -985150958, -360504705, -338926527, -429529620, 1868643822,
                497200693, 514967316, 553000234, -1448913182, 337173746, 2086981669, 301869301, -3754352, -1512583048,
                -171259500, 1112490239, -568538694, -1940535850, -712152462, -1964796154, 2138272507, 200636960,
                -361625192, -1150054696, 1680446966, -1035306597, -473191839, 828846985, 2079964168, -126025684,
                193547098, -130239758, -756458479, 1313693391, -453139541, -19992248, 129035570, -112460079, 1019950712,
                1669008661, -1131243404, -2066509040, -550090541, 1967924493, 326308968, 1924455839, 256154072,
                -80881534, -2068720820, 448277233, -642278483, -1180147811, 1607094519, 1308454030, -675392471,
                -2140511257, 1828853030, 1128602914, -1509283271, 703028585, -505072269, -1588124563, -69860625,
                1566951171, 471018310, 1073834119, -1541342078, -1150882812, 1091678885, 893357174, 880407022,
                1544457405, -1168056310, 1156564035, -144334838, 1278795902, 458646360, -169231062, 158163741,
                735189974, 113541995, -1716560061, -15002613, 622836725, 667666502, -653035233, -2114624625, 501837867,
                1420814499, 805723811, -478233292, -1243677823, 652735135, -53893238, 869806111, 220758772, 523399337,
                142646430, 242820644 };
    }

    private List<String> getShingles(int n, List<String> input) {
        List<String> shingles = new ArrayList<>();

        for (int i = 0; i < input.size() - n; i++) {
            String shingle = "";
            for (int j = 0; j < n; j++) {
                shingle += input.get(i + j) + " ";
            }
            shingles.add(shingle);
        }
        return shingles;
    }

    private List<Long> calculateMinHash(List<String> shingles) {
        List<List<Long>> allHashes = new ArrayList<>();
        List<Long> minHashes = new ArrayList<>();
        List<Long> firstHashes = new ArrayList<>();

        for (int i = 0; i < shingles.size(); i++) {
            firstHashes.add((long) shingles.get(i).hashCode());
        }
        minHashes.add(Collections.min(firstHashes));

        for (int j : this.randomNmbr) {
            List<Long> tmp = new ArrayList<>();
            for (Long hash : firstHashes) {
                tmp.add(hash ^ j);
            }
            minHashes.add(Collections.min(tmp));
        }

        return minHashes;
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
                        List<String> shingles = this.getShingles(5, fnOps);
                        List<Long> minHashes = this.calculateMinHash(shingles);
                        function.setMinHashes(minHashes);
                        function.setOffset(functionInfo.get("offset").getAsInt());
                        function.setNmbBands(config.get("NMB_BANDS").getAsInt());
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