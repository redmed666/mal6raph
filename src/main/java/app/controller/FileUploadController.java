package app.controller;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.xml.bind.DatatypeConverter;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.neo4j.driver.v1.Record;
import org.neo4j.driver.v1.Value;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.MvcUriComponentsBuilder;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import app.Application;
import app.analyzer.Analyzer;
import app.sample.Function;
import app.sample.Sample;
import app.storage.StorageFileNotFoundException;
import app.storage.StorageService;
import app.util.Hash;

@Controller
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
            System.out.println(e.getMessage());
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
            System.out.println(e.getMessage());
            System.exit(1);
            return;
        }
        this.neo4jDb = new app.model.Model(config.get("NEO4JURI").getAsString(), config.get("USER").getAsString(),
                config.get("PASSWORD").getAsString());
    }

    @GetMapping("/")
    public String listUploadedFiles(Model model) throws IOException {

        model.addAttribute("files",
                storageService.loadAll()
                        .map(path -> MvcUriComponentsBuilder
                                .fromMethodName(FileUploadController.class, "serveFile", path.getFileName().toString())
                                .build().toString())
                        .collect(Collectors.toList()));

        return "uploadForm";
    }

    @GetMapping("/files/{filename:.+}")
    @ResponseBody
    public ResponseEntity<Resource> serveFile(@PathVariable String filename) {

        Resource file = storageService.loadAsResource(filename);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + file.getFilename() + "\"")
                .body(file);
    }

    @GetMapping("/sample/{sha256Sample}")
    @ResponseBody
    public String findRelSample(@PathVariable String sha256Sample) {
        sha256Sample = sha256Sample.toUpperCase();
        String result = "";
        List<Function> functions = new ArrayList<Function>();
        List<List<Function>> functionsSimilSize = new ArrayList<List<Function>>();

        String query = this.neo4jDb.createQueryGetFunctions(sha256Sample);
        List<Record> rFunctions = this.neo4jDb.sendQuery(query);

        for (Record rFunction : rFunctions) {
            Function function = new Function();
            List<String> ops = new ArrayList<String>();

            Value vOps = rFunction.get("f").get("ops");
            for (Value vOp : vOps.values()) {
                ops.add(vOp.asString());
            }

            function.setSha256(rFunction.get("f").get("sha256").asString());
            function.setOps(ops);
            function.setSize(rFunction.get("f").get("size").asInt());
            functions.add(function);

            String queryFctSimil = neo4jDb.createQueryGetFunctionsSameSize(function,
                    config.get("DIFF_SIZE_FCT").getAsFloat(), sha256Sample);

            List<Record> rFunctionsSize = neo4jDb.sendQuery(queryFctSimil);
            List<Function> functionsSameSize = new ArrayList<Function>();
            Analyzer anal = new Analyzer();
            for (Record rFunctionSize : rFunctionsSize) {
                Function fctSameSize = new Function();
                fctSameSize.setMd5(rFunctionSize.get("f").get("md5").asString());
                fctSameSize.setSha256(rFunctionSize.get("f").get("sha256").asString());
                Value sOps = rFunctionSize.get("f").get("ops");
                List<String> opsFctSimil = new ArrayList<String>();
                for (Value sOp : sOps.values()) {
                    opsFctSimil.add(sOp.asString());
                }
                fctSameSize.setOps(opsFctSimil);

                functionsSameSize.add(fctSameSize);
            }

            List<Map<String, Float>> similarities = new ArrayList<Map<String, Float>>();
            try {
                anal.analyzeSimil(function, functionsSameSize, similarities, config);
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

        return result;
    }

    @PostMapping("/")
    public String handleFileUpload(@RequestParam("file") MultipartFile file, RedirectAttributes redirectAttributes)
            throws Exception {

        storageService.store(file);
        Path filepath = storageService.load(StringUtils.cleanPath(file.getOriginalFilename()));

        File fileOpened = new File(filepath.toString());

        String sha256Sample = toHex(Hash.SHA256.checksum(fileOpened));
        String md5Sample = toHex(Hash.MD5.checksum(fileOpened));

        Analyzer anal = new Analyzer();
        Sample sample = new Sample();
        sample = anal.analyzeSample(filepath.toString(), config);
        sample.setSha256(sha256Sample);
        String querySampleExists = neo4jDb.createQuerySampleExists(sha256Sample);
        List<Record> resultSampleExists = neo4jDb.sendQuery(querySampleExists);

        if (resultSampleExists.size() > 0) {
            neo4jDb.close();
            return "Sample already exists";
        }

        sample.setMd5(md5Sample);

        String newSampleQuery = neo4jDb.createQueryNewSample(sample);
        String newFunctionsQuery = neo4jDb.createQueryNewFunctions(sample);
        String newStringsQuery = neo4jDb.createQueryNewStrings(sample);

        neo4jDb.sendQuery(newSampleQuery);
        neo4jDb.sendQuery(newFunctionsQuery);
        neo4jDb.sendQuery(newStringsQuery);

        return "redirect:/";
    }

    @ExceptionHandler(StorageFileNotFoundException.class)
    public ResponseEntity<?> handleStorageFileNotFound(StorageFileNotFoundException exc) {
        return ResponseEntity.notFound().build();
    }

    private static String toHex(byte[] bytes) {
        return DatatypeConverter.printHexBinary(bytes);
    }

}
