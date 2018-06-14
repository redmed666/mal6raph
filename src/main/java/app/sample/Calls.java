package app.sample;

import java.util.ArrayList;
import java.util.List;

import org.neo4j.ogm.annotation.EndNode;
import org.neo4j.ogm.annotation.GeneratedValue;
import org.neo4j.ogm.annotation.Id;
import org.neo4j.ogm.annotation.RelationshipEntity;
import org.neo4j.ogm.annotation.StartNode;

@RelationshipEntity(type = "CALLS")
public class Calls {
    @Id
    @GeneratedValue
    private Long id;
    private List<String> calls = new ArrayList<>();

    @StartNode
    private Sample sample;

    @EndNode
    private Function function;

    public Calls(Sample sample, Function function) {
        this.sample = sample;
        this.function = function;
    }

    /**
     * @return the id
     */
    public Long getId() {
        return id;
    }

    /**
     * @return the calls
     */
    public List<String> getCalls() {
        return calls;
    }

    /**
     * @return the function
     */
    public Function getFunction() {
        return function;
    }

    /**
     * @return the sample
     */
    public Sample getSample() {
        return sample;
    }
}