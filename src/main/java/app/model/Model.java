package app.model;

import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.google.gson.JsonElement;

import org.neo4j.driver.v1.AuthTokens;
import org.neo4j.driver.v1.Driver;
import org.neo4j.driver.v1.GraphDatabase;
import org.neo4j.driver.v1.Session;
import org.neo4j.driver.v1.Value;
import org.neo4j.driver.v1.exceptions.NoSuchRecordException;

import app.sample.Function;
import app.sample.Sample;

public class Model implements AutoCloseable {
    private final Driver driver;

    public Model(String uri, String user, String password) {
        driver = GraphDatabase.driver(uri, AuthTokens.basic(user, password));
    }

    @Override
    public void close() throws Exception {
        driver.close();
    }

    public Iterator<Map<String, Object>> sendQuery(String query) throws NoSuchRecordException {
        try (Session session = driver.session()) {
            List<Map<String, Object>> list = session.run(query).list(r -> r.asMap(Model::convert));
            return list.iterator();
        }
    }

    static Object convert(Value value) {
        switch (value.type().name()) {
        case "PATH":
            return value.asList(Model::convert);
        case "NODE":
        case "RELATIONSHIP":
            return value.asMap();
        }
        return value.asObject();
    }

    public String createQueryGetAll() {
        String query = String.format(
                "MATCH (s:Sample)-[:CALLS]->(f:Function) RETURN s.sha256 as sample, collect(f.sha256) as functions");
        return query;
    }

    public String createQueryGetSamples() {
        String query = "MATCH (s:Sample) RETURN collect(s.sha256) as samples";
        return query;
    }

    public String createQuerySampleExists(String sha256Sample) {
        String query = String.format("MATCH (sample_%s:Sample {sha256:'%s'})\n", sha256Sample, sha256Sample);
        query += String.format("RETURN sample_%s.sha256 as sha256\n", sha256Sample);
        return query;
    }

    public String createQueryGetSampleSimilFcts(String sha256Sample) {
        String query = String.format(
                "MATCH (s1:Sample {sha256:'%s'})-[:CALLS]->(f1:Function)-[:SIMILAR_TO]-(f2:Function)<-[:CALLS]-(s2:Sample) RETURN s1.sha256 as sampleSrc, collect(f1.sha256) as fctSampleSrc, collect(f2.sha256) as fctSampleTrg, collect(s2.sha256) as samplesTrg",
                sha256Sample);
        return query;
    }

    public String createQueryNewSample(Sample sample) {
        String sha256 = sample.getSha256();
        String query = String.format("CREATE (sample_%s:Sample)\n", sha256);

        query += String.format("SET sample_%s.md5 = '%s'\n", sha256, sample.getMd5());

        query += String.format("SET sample_%s.sha256 = '%s'\n", sha256, sha256);

        query += String.format("SET sample_%s.arch = '%s'\n", sha256, sample.getArch());

        query += String.format("SET sample_%s.bits = %d\n", sha256, sample.getBits());

        query += String.format("RETURN sample_%s.id\n", sha256);

        return query;
    }

    public String createQueryNewFunctions(Sample sample) {
        List<Function> functions = sample.getFunctions();
        String query = "";
        Set<String> listSha256Fct = new HashSet<String>();

        if (functions.size() != 0) {
            query = String.format("MATCH (sample_%s:Sample {sha256:'%s'})\n", sample.getSha256(), sample.getSha256());
            for (Function function : functions) {
                String fnSha256 = function.getSha256();
                if (!listSha256Fct.contains(fnSha256)) {
                    listSha256Fct.add(fnSha256);
                    query += String.format("CREATE (function_%s:Function)\n", fnSha256);
                    query += String.format("SET function_%s.md5 = '%s'\n", fnSha256, function.getMd5());
                    query += String.format("SET function_%s.sha256 = '%s'\n", fnSha256, fnSha256);
                    query += String.format("SET function_%s.size = %d\n", fnSha256, function.getSize());
                    query += String.format("SET function_%s.arch = '%s'\n", fnSha256, function.getArch());
                    query += String.format("SET function_%s.bits = %d\n", fnSha256, function.getBits());
                    query += String.format("SET function_%s.ops = %s\n", fnSha256, function.getOps().toString());
                    query += String.format("SET function_%s.offset = %d\n", fnSha256, function.getOffset());
                    query += String.format("SET function_%s.already_anal_by = []\n", fnSha256);
                    query += String.format("SET function_%s.minHashes = %s\n", fnSha256,
                            function.getMinHashes().toString());
                    int sizeBand = function.getMinHashes().size() / function.getNmbBands();
                    for (int i = 0; i < function.getNmbBands(); i++) {
                        query += String.format("SET function_%s.band_%d = %s\n", fnSha256, i,
                                function.getMinHashes().subList(i * sizeBand, (i + 1) * sizeBand).toString());
                    }
                    query += String.format("CREATE (sample_%s)-[:CALLS]->(function_%s)\n", sample.getSha256(),
                            fnSha256);
                }
            }
        }

        return query;
    }

    public String createQueryNewStrings(Sample sample) {
        String sha256 = sample.getSha256();
        String query = "";
        if (sample.getStrings().size() > 0) {
            query = String.format("MATCH (sample_%s :Sample {sha256:'%s'})\n", sha256, sha256);
            for (String string : sample.getStrings()) {
                String stringSanit = string.replace("=", "_").replace("+", "__").replace("/", "___").replace("\"", "");
                query += String.format("CREATE (string_%s:String)\n", stringSanit);
                query += String.format("SET string_%s.string='%s'\n", stringSanit, string);
                query += String.format("CREATE (sample_%s)-[:HAS]->(string_%s)\n", sha256, stringSanit);
            }
        }
        return query;
    }

    public String createQueryNewImports(Sample sample) {
        String sha256 = sample.getSha256();
        String query = "";

        if (sample.getImports().size() > 0) {
            query = String.format("MATCH (sample_%s:Sample {sha256:'%s'})\n", sha256, sha256);
            for (JsonElement imported : sample.getImports()) {
                String importedSanit = imported.getAsJsonObject().get("name").getAsString().replace(".", "_");
                query += String.format("CREATE (import_%s:Import)\n", importedSanit);
                query += String.format("SET import_%s.name = '%s'\n", importedSanit,
                        imported.getAsJsonObject().get("name").getAsString());
                query += String.format("CREATE (sample_%s)-[:IMPORTS]->(import_%s)\n", sha256, importedSanit);
            }
        }

        return query;
    }

    public String createQueryGetFunctionsSameSize(Function function, Float percentDiffSize, String sha256Sample) {
        float size = (float) function.getSize();
        float more = size * (1.0f - percentDiffSize);
        float less = size * (1.0f + percentDiffSize);
        String query = String.format(
                "MATCH (s:Sample {sha256:'%s'}), (f1:Function), (f2:Function {sha256:'%s'}) WHERE f1.size <= %d AND f1.size >= %d AND NOT (s)-[:CALLS]->(f1) AND NOT (f1)-[:SIMILAR_TO]-(f2) AND (NOT f2.sha256 IN f1.already_anal_by) AND (NOT f1.sha256 in f2.already_anal_by) SET f1.already_anal_by = f1.already_anal_by + f2.sha256 SET f2.already_anal_by = f2.already_anal_by + f1.sha256 RETURN f1\n",
                sha256Sample, function.getSha256(), (int) less, (int) more);
        return query;
    }

    public String createQueryGetSimilHashes(Function function, String sha256Sample) {
        String query = String.format("MATCH (f1:Function {sha256:'%s'}), (s:Sample {sha256:'%s'}), (f2:Function) WHERE",
                function.getSha256(), sha256Sample);
        query += String.format(" NOT (s)-[:CALLS]->(f2) ");
        query += String.format(" AND (s)-[:CALLS]->(f1) ");
        query += String.format(" AND NOT (f1)-[:SIMILAR_TO]-(f2) ");
        query += String.format(" AND NOT ID(f2) IN f1.already_anal_by ");
        query += String.format(" AND NOT ID(f1) in f2.already_anal_by ");
        query += String.format(" AND (");
        for (int i = 0; i < function.getNmbBands(); i++) {
            if (i != function.getNmbBands() - 1) {
                query += String.format("f1.band_%d = f2.band_%d OR ", i, i);
            } else {
                query += String.format("f1.band_%d = f2.band_%d)", i, i);
            }
        }
        query += " SET f1.already_anal_by = f1.already_anal_by + ID(f2) ";
        query += " SET f2.already_anal_by = f2.already_anal_by + ID(f1) ";
        query += " RETURN f2\n";

        return query;
    }

    public String createQueryGetScore(Function functionSrc, Function functionTrg) {
        String query = String.format(
                "MATCH (f1:Function {sha256:'%s'}), (f2:Function {sha256:'%s'}) RETURN length(FILTER(hash in f2.minHashes WHERE hash in f1.minHashes)) AS score\n",
                functionSrc.getSha256(), functionTrg.getSha256());
        return query;
    }

    public String createQueryFunctionsSimilar(String sha256FnAnalyzed, String sha256FnComparedTo, Float similarity) {
        String query = String.format(
                "MATCH (function_1:Function {sha256:'%s'}), (function_2:Function {sha256:'%s'}) WHERE NOT (function_1)-[:SIMILAR_TO]-(function_2) AND NOT ID(function_1) = ID(function_2)\n",
                sha256FnAnalyzed, sha256FnComparedTo);
        query += String.format(Locale.ROOT, "MERGE (function_1)-[:SIMILAR_TO {similarity: %f}]->(function_2)\n",
                similarity);

        return query;
    }

    public String createQuerySampleCallsFunctions(String sha256Sample, String sha256Fn) {
        String query = String.format("MATCH (sample_%s:Sample {sha256:'%s'}), (function_%s:Function {sha256:'%s'})\n",
                sha256Sample, sha256Sample, sha256Fn, sha256Fn);

        query += String.format("CREATE (sample_%s)-[:CALLS]->(function_%s)\n", sha256Sample, sha256Fn);

        return query;
    }

    public String createQueryGetFunctions(String sha256Sample) {
        String query = String.format("MATCH (s:Sample {sha256:'%s'})-[:CALLS]->(f)\n", sha256Sample);
        query += "RETURN f\n";

        return query;
    }

    public String createQueryTestFnExist(String sha256Sample) {
        String query = String.format("MATCH (sample_%s:Sample {sha256:'%s'})\n", sha256Sample, sha256Sample);
        query += String.format("RETURN sample_%s\n", sha256Sample);
        return query;
    }

}