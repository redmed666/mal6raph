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
        this.randomNmbr = new int[] { 1876619844, -1783674942, -1470020720, -1020507094, -552251429, -1849442604,
                -1588111829, -638449608, 787131536, -214929784, 870738239, 1152547545, 794466599, -1667290658,
                -1315489158, 467203778, 1619636071, 1166461761, 202235103, -9857966, -281121582, 1275953411, -737893504,
                630170784, 1031437114, -114694558, 1481548754, 1144180119, -1677751021, 1404251062, 141299149,
                -1138984858, 988238793, -152676013, 464144008, 1877687783, -902791441, 1932335418, -1705774787,
                659863418, 1070265784, 1568639234, -337902639, 162063910, -1103902071, -1591393882, -984582570,
                -269365401, 645922705, -6578675, 1221592987, 1964033474, -585297566, -1205544558, -4495089, 1322247675,
                -1807460444, -1601590299, -1938973485, -1690679596, 500772751, -1585973231, -853033444, 574641126,
                752064035, 1415224903, -3803012, 390854066, 1933273699, 1669527795, 606748949, -1271561205, 1301063636,
                26734915, -317472765, -1293328358, 922056523, -148442638, -13146194, 1618991555, 296536504, 276256349,
                -1578911350, 1860369251, 1089288551, 1213210322, -551078478, -1678429717, 457796304, -531335298,
                1627405703, 37136216, -1131170512, 702408256, -1272241759, 1145963410, -1835892963, 659838628,
                -111956335, 552374203, -591584016, 910043295, 1376014428, -1082047369, -1798849398, -1033819521,
                -186038133, -780843532, -885115669, -927600694, 1264516672, 1815666918, -624654697, 1446297230,
                1901241597, -1000592261, -688363459, 462957878, -1023593110, -221336541, -731089584, 206717676,
                -1207799088, -54853627, -728238644, -75091935, -1555815961, -401916315, -223705632, -1980604447,
                200281837, 274476960, -361844090, -1473414218, -1176999749, -1926506473, -820815360, 1363178035,
                1970618288, 520700118, 1007338368, 1422509170, 1249454053, -517673514, 945371729, -1494733620,
                785522917, 1139373809, -1255621986, 814181604, -1725638681, 518001503, -1066860966, -228931756,
                1426731754, -1636004019, 1002757701, -837423696, 566666528, -1022128673, 1752591818, -825866896,
                1377614742, -1328629548, 478454265, -505448278, -1808407776, -1795031248, 1042426228, -1018313866,
                -1761585039, 200445221, 1885377814, -1864679827, -399181301, -201544688, 873009055, -1849872009,
                631361268, -1365951446, -1174677237, -1782422750, 1035265611, 757743792, 1548555356, -1756969307,
                860337536, -781494759, 1427531867, -11932808, -695220578, 1031701702, -1259969056, 1067471245,
                -1228492985, -337890596, 775106492, 1392514267, 1044959935, -1403418222, 700210903, 306131186,
                -1035450928, 113148613, 1319784564, -102711729, 1058668819, -277321518, -1825933941, -1011696290,
                -1063105057, -639282945, 1942118689, -854593426, -1923904251, -1639036212, -1304530910, 297156231,
                -805335209, -1082110684, -935806064, -1431376262, 550746182, -1885328765, 1733665448, 107182193,
                -1535457123, 190104258, 1262468443, -1503328814, 1637367014, 1435067955, -706891379, 1827112722,
                -1135060355, -592158157, -258771117, 579470549, -416891001, -118547749, 98452889, 106457121, -113999971,
                -1546862154, -588305243, -1118282928, -1572175558, -527285737, -1844896545, 671639661, 1036733300,
                834139012, -1228016836, 147755275, 340545763, 781071875, -1410407749, -439697005, 1532508834, 545496691,
                -1896372171, 239042436, -662120765, 1863714539, 1016468762, -604822312, 519185476, 901042410,
                -323116223, 1102549866, 1657278211, 1731226459, -196397471, 747433902, 477856633, 846015903,
                -1208901807, -780150837, -797936501, -1259487902, -267796592, 1940371642, 1040774801, -379058952,
                -1491061177, 1591123496, 1141141419, -1419761484, -1558687319, 1682682226, -1656058633, 226066191,
                1723511795, 1483391981, 299983520, -48221003, -1023284316, -1499406679, 997595643, -339468648,
                1699463017, -902650660, -668970811, -205782789, -917579317, -1179068116, -863207083, 1201925231,
                1626759696, 1632404810, -1845065758, -1023122533, 845671399, -732817034, -1081464853, 567573544,
                834370872, 252470665, -1468272326, 434187051, 1311358962, 1306107564, -1077451237, 385299649, 189282309,
                754263773, 1879976976, -1146228567, 1486916374, -814841689, 1477030309, -651650291, -870132121,
                -1406899120, -1418733429, -979398794, -495455405, -51862005, 1120040207, -546969324, 296252035,
                -377408658, 1355159655, -60778911, -1650762972, -1384512174, 1339526301, 1779025501, 1145622415,
                1848859716, 475508352, 866830981, -1582234511, -706769524, 1921522544, -85201906, 1413615512, 517050213,
                628588389, -733995041, 609226598, 718001771, 1477129495, 792166833, 486520008, 931798991, 1353117137,
                1003760083, 1000304678, 1840776965, 1485775158, 528818434, -512666577, -1687430976, 1411764427,
                -1521171301, -1691297564, 738300830, -873188888, -211731243, 1862971400, -1679948920, 755986114,
                184176452, 973756847, -758080335, 809918453, 1056779947, -1998749033, 79896907, 186286432, 1509245729,
                -1996862887, 1794349660, -1653336849, 378707296, 1992371126, -770948953, -968510180 };
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