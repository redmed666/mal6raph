package app.controllers;

import static org.neo4j.helpers.collection.MapUtil.map;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.bind.DatatypeConverter;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import app.Application;
import app.analyzer.Analyzer;
import app.sample.Function;
import app.sample.Sample;
import app.storage.StorageFileNotFoundException;
import app.storage.StorageService;
import app.util.Hash;

@RestController
public class FileUploadController {

    private final StorageService storageService;
    private JsonObject config;
    private app.model.Model neo4jDb;

    static String readFile(String path, Charset encoding) throws IOException {
        byte[] encoded = Files.readAllBytes(Paths.get(path));
        return new String(encoded, encoding);
    }

    private static JsonObject parseConfig(String configPath) throws Exception {

        JsonObject config = new JsonObject();

        JsonParser parser = new JsonParser();
        String config_str = readFile(configPath, StandardCharsets.UTF_8);
        config = parser.parse(config_str).getAsJsonObject();
        return config;
    }

    private static CommandLine parseCLine(String... args) throws ParseException {
        Options options = new Options();
        Option config_path = new Option("c", "config", true, "Config file path");
        config_path.setRequired(true);
        options.addOption(config_path);

        CommandLineParser cli_parser = new DefaultParser();
        HelpFormatter cli_formatter = new HelpFormatter();
        CommandLine cmd;

        try {
            cmd = cli_parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println("OPTIONS:" + e.getMessage());
            cli_formatter.printHelp("mal6raph", options);
            throw e;
        }
        return cmd;
    }

    @Autowired
    public FileUploadController(StorageService storageService) {
        config = new JsonObject();
        this.storageService = storageService;

        CommandLine cmd;
        try {
            cmd = parseCLine(Application.ARGS);
        } catch (ParseException e) {
            System.exit(1);
            return;
        }

        try {
            config = parseConfig(cmd.getOptionValue("config"));
        } catch (Exception e) {
            System.out.println("CONFIG: " + e.getMessage());
            System.exit(1);
            return;
        }
        this.neo4jDb = new app.model.Model(config.get("NEO4JURI").getAsString(), config.get("USER").getAsString(),
                config.get("PASSWORD").getAsString());
    }

    @GetMapping(value = "/samples", produces = "application/json;charset=UTF-8")
    @ResponseBody
    public String getSamples() {
        String query = neo4jDb.createQueryGetSamples();
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        Iterator<Map<String, Object>> result = neo4jDb.sendQuery(query);
        List samples = new ArrayList<>();
        while (result.hasNext()) {
            Map<String, Object> row = result.next();
            for (Object sampleSha256 : (Collection) row.get("samples")) {
                samples.add((String) sampleSha256);
            }
        }
        String res = gson.toJson(map("samples", samples));
        return res;
    }

    @GetMapping(value = "/all", produces = "application/json;charset=UTF-8")
    @ResponseBody
    public String getAll() {
        String query = neo4jDb.createQueryGetAll();
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        Iterator<Map<String, Object>> result = neo4jDb.sendQuery(query);
        List nodes = new ArrayList<>();
        List rels = new ArrayList<>();

        int i = 0;

        while (result.hasNext()) {
            Map<String, Object> row = result.next();
            nodes.add(map("name", row.get("sample"), "label", "sample", "_color", "firebrick"));
            int target = i;
            i++;
            for (Object fnSha256 : (Collection) row.get("functions")) {
                Map<String, Object> function = map("name", fnSha256, "label", "function", "_color", "lightseagreen");
                int source = nodes.indexOf(function);
                if (source == -1) {
                    nodes.add(function);
                    source = i++;
                }
                rels.add(map("sid", source, "tid", target, "_color", "beige"));
            }
        }
        return gson.toJson(map("nodes", nodes, "links", rels));
    }

    @GetMapping("/sample/{sha256Sample}")
    @ResponseBody
    public String findRelSample(@PathVariable String sha256Sample) {
        sha256Sample = sha256Sample.toUpperCase();
        String result = "";

        List<Function> functions = new ArrayList<>();
        List<List<Function>> functionsSimilSize = new ArrayList<>();

        String query = this.neo4jDb.createQueryGetFunctions(sha256Sample);
        Iterator<Map<String, Object>> rFunctions = this.neo4jDb.sendQuery(query);

        while (rFunctions.hasNext()) {
            Map<String, Object> rFunction = rFunctions.next();
            Map<String, Object> f = (Map<String, Object>) rFunction.get("f");
            Function function = new Function();
            List<String> ops = (List<String>) f.get("ops");

            String fnSha256 = f.get("sha256").toString();
            function.setSha256(fnSha256);
            function.setOps(ops);
            function.setSize((Long) f.get("size"));
            function.setMinHashes((List<Long>) f.get("minHashes"));
            functions.add(function);

            String queryFctSimil = neo4jDb.createQueryGetSimilHashes(function, sha256Sample);

            Iterator<Map<String, Object>> rFunctionSameHash = neo4jDb.sendQuery(queryFctSimil);
            List<Function> functionsSameHash = new ArrayList<Function>();
            Analyzer anal = new Analyzer();

            while (rFunctionSameHash.hasNext()) {
                Map<String, Object> rFunctionHash = rFunctionSameHash.next();
                Map<String, Object> fHash = (Map<String, Object>) rFunctionHash.get("f");

                Function fctSameHash = new Function();
                fctSameHash.setMd5((String) fHash.get("md5"));
                fctSameHash.setSha256((String) fHash.get("sha256"));
                List<String> opsFctSimil = (List<String>) fHash.get("ops");
                fctSameHash.setOps(opsFctSimil);
                List<Long> minHashes = (List<Long>) fHash.get("minHashes");
                fctSameHash.setMinHashes(minHashes);

                functionsSameHash.add(fctSameHash);
            }
            if (!functionsSameHash.isEmpty()) {
                List<Map<String, Float>> similarities = new ArrayList<Map<String, Float>>();
                try {
                    anal.analyzeSimil(function, functionsSameHash, similarities, config);
                } catch (Exception e) {
                    System.out.println(e.getMessage());
                }

                for (Map<String, Float> similarity : similarities) {
                    similarity.forEach((key, value) -> {
                        String queryFcnSimil = neo4jDb.createQueryFunctionsSimilar(function.getSha256(), key, value);
                        neo4jDb.sendQuery(queryFcnSimil);
                    });
                }
            }
        }

        String querySampleSimilFct = neo4jDb.createQueryGetSampleSimilFcts(sha256Sample);
        Gson gson = new GsonBuilder().disableHtmlEscaping().create();
        Iterator<Map<String, Object>> resultQuery = neo4jDb.sendQuery(querySampleSimilFct);
        List nodes = new ArrayList<>();
        List rels = new ArrayList<>();

        int i = 0;

        while (resultQuery.hasNext()) {
            Map<String, Object> row = resultQuery.next();
            nodes.add(map("name", row.get("sampleSrc"), "label", "sample", "_color", "firebrick"));
            int target = i;
            i++;
            List<String> fctsSampleSrc = (List) row.get("fctSampleSrc");
            List<String> fctsSampleTrg = (List) row.get("fctSampleTrg");
            List<String> samplesTrg = (List) row.get("samplesTrg");

            // fctSampleSrc == sha256 of function called by sample analyzed
            for (int j = 0; j < fctsSampleSrc.size(); j++) {
                // checks if fct node exists, if not, adds it
                Map<String, Object> fctSrc = map("name", (String) fctsSampleSrc.get(j), "label", "function", "_color",
                        "lightseagreen");
                int sourceFctSrc = nodes.indexOf(fctSrc);
                if (sourceFctSrc == -1) {
                    nodes.add(fctSrc);
                    sourceFctSrc = i++;
                }
                // rel = CALLS from sampleSrc to fctSampleSrc
                rels.add(map("sid", sourceFctSrc, "tid", target, "_color", "beige", "name", "CALLS"));

                Map<String, Object> fctTrg = map("name", (String) fctsSampleTrg.get(j), "label", "function", "_color",
                        "cornflowerblue");
                int sourceFctTarg = nodes.indexOf(fctTrg);
                if (sourceFctTarg == -1) {
                    nodes.add(fctTrg);
                    sourceFctTarg = i++;
                }
                // rel = SIMILAR_TO from sampleSrc to fctSampleSrc
                rels.add(map("sid", sourceFctSrc, "tid", sourceFctTarg, "_color", "darkorchid", "name", "SIMILAR_TO"));

                Map<String, Object> sampleTrg = map("name", (String) samplesTrg.get(j), "label", "sample", "_color",
                        "deeppink");
                int sourceSampleTarg = nodes.indexOf(sampleTrg);
                if (sourceSampleTarg == -1) {
                    nodes.add(sampleTrg);
                    sourceSampleTarg = i++;
                }
                // rel = CALLS from SampleTarg to fctSampleTarg
                rels.add(map("sid", sourceSampleTarg, "tid", sourceFctTarg, "_color", "beige", "name", "CALLS"));

            }

        }
        return gson.toJson(map("nodes", nodes, "links", rels));
    }

    @PostMapping("/upload")
    @ResponseBody
    public String handleFileUpload(@RequestParam("file") MultipartFile file) throws Exception {

        storageService.store(file);
        Path filepath = storageService.load(StringUtils.cleanPath(file.getOriginalFilename()));

        File fileOpened = new File(filepath.toString());

        String sha256Sample = toHex(Hash.SHA256.checksum(fileOpened)).replace("\n", "");
        String md5Sample = toHex(Hash.MD5.checksum(fileOpened)).replace("\n", "");

        Analyzer anal = new Analyzer();
        Sample sample = new Sample();
        sample = anal.analyzeSample(filepath.toString(), config);
        sample.setSha256(sha256Sample);
        String querySampleExists = neo4jDb.createQuerySampleExists(sha256Sample);
        Iterator<Map<String, Object>> resultSampleExists = neo4jDb.sendQuery(querySampleExists);

        if (resultSampleExists.hasNext()) {
            return String.format("{\"msg\":\"Sample already exists\", \"sha256\":\"%s\"}", sha256Sample);
        }

        sample.setMd5(md5Sample);

        String newSampleQuery = neo4jDb.createQueryNewSample(sample);
        String newFunctionsQuery = neo4jDb.createQueryNewFunctions(sample);
        String newStringsQuery = neo4jDb.createQueryNewStrings(sample);

        neo4jDb.sendQuery(newSampleQuery);
        neo4jDb.sendQuery(newFunctionsQuery);
        neo4jDb.sendQuery(newStringsQuery);

        return String.format("{\"sha256\":\"%s\"}", sha256Sample);
    }

    @ExceptionHandler(StorageFileNotFoundException.class)
    public ResponseEntity<?> handleStorageFileNotFound(StorageFileNotFoundException exc) {
        return ResponseEntity.notFound().build();
    }

    private static String toHex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

}
