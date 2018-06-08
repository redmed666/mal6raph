package app.model;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

import com.google.gson.JsonElement;

import org.neo4j.driver.v1.AuthTokens;
import org.neo4j.driver.v1.Driver;
import org.neo4j.driver.v1.GraphDatabase;
import org.neo4j.driver.v1.Record;
import org.neo4j.driver.v1.Session;
import org.neo4j.driver.v1.StatementResult;
import org.neo4j.driver.v1.Transaction;
import org.neo4j.driver.v1.TransactionWork;
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

    public List<Record> sendQuery(String query) throws NoSuchRecordException {
        Session session = driver.session();
        List<Record> result = session.writeTransaction(new TransactionWork<List<Record>>() {
            @Override
            public List<Record> execute(Transaction tx) {
                StatementResult result_transac = tx.run(query);
                return result_transac.list();
            }
        });
        return result;
    }

    public String createQuerySampleExists(String sha256Sample) {
        String query = String.format("MATCH (sample_%s:Sample {sha256:'%s'})\n", sha256Sample, sha256Sample);
        query += String.format("RETURN sample_%s\n", sha256Sample);
        return query;
    }

    public String createQueryNewSample(Sample sample) {
        String sha256 = sample.getSha256();
        String query = String.format("CREATE (sample_%s:Sample)\n", sha256);

        query += String.format("SET sample_%s.md5 = '%s'\n", sha256, sample.getMd5());

        query += String.format("SET sample_%s.sha256 = '%s'\n", sha256, sha256);

        query += String.format("SET sample_%s.imports = '%s'\n", sha256, sample.getImports().toString());

        query += String.format("SET sample_%s.exports = '%s'\n", sha256, sample.getExports().toString());

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
                "MATCH (s:Sample {sha256:'%s'}), (f:Function), (f2:Function {sha256:'%s'}) WHERE f.size <= %d AND f.size >= %d AND NOT (s)-[:CALLS]->(f) AND NOT (f)-[:SIMILAR_TO]->(f2) AND NOT (f2)-[:SIMILAR_TO]->(f) RETURN f\n",
                sha256Sample, function.getSha256(), (int) less, (int) more);
        return query;
    }

    public String createQueryFunctionsSimilar(String sha256FnAnalyzed, String sha256FnComparedTo, Float similarity) {
        String query = String.format(
                "MATCH (function_%s:Function {sha256:'%s'}), (function_%s:Function {sha256:'%s'}) WHERE NOT (function_%s)-[:SIMILAR_TO]->(function_%s) OR NOT (function_%s)-[:SIMILAR_TO]->(function_%s)\n",
                sha256FnAnalyzed, sha256FnAnalyzed, sha256FnComparedTo, sha256FnComparedTo, sha256FnAnalyzed,
                sha256FnComparedTo, sha256FnComparedTo, sha256FnAnalyzed);
        query += String.format(Locale.ROOT, "MERGE (function_%s)-[:SIMILAR_TO {similarity: %f}]->(function_%s)\n",
                sha256FnAnalyzed, similarity, sha256FnComparedTo);

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