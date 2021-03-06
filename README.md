# Mal6raph

## Why "Mal6raph"?

Most important question indeed! Just a bad name coming from: radare2 + neo4j = Mal6raph :D

## WTF is Mal6raph?

It is a kind of framework which can be used to compare samples between them from a code persective.
For example, it could be a tool which gives you the answer "Which samples have X functions similar with the sample I give you?".
It is not attended to become a silver bullet for malware analysis. Just a tool that can give you elements for your analysis.
One of the goal is to avoid lost of previous analysis by saving information collected of precedent samples already reverse engineered.

## Results
The green bubbles are samples and red ones are functions.
Different types of links:
* CALLS: samples calls this function
* SIMILAR_TO: function is similar to another one.

![Alt text](./docs/img/graph.png?raw=true "Result of a query after analysis")

Result presented here is a result from the query: 
```bash
MATCH (s1:Sample)-[:CALLS]->(f1:Function)-[:SIMILAR_TO]->(f2:Function)<-[:CALLS]-(s2:Sample) RETURN s1,f1,s2,f2
```

in the neo4j web application.

## Tradeoffs
In order to be able to analyze data quite efficiently, I had to do some tradeoffs:
* The similarity between functions has to be understood as ratio of same kind of opcodes. So, I am not comparing mov eax, ebx with mov ecx, edx but only MOV and MOV.
* All the functions are not taken into account, only the ones with a size greater than the threshold defined in config.json
* Same thing for the strings

## How to use it?
`./gradlew build && ./gradlew jar`

In one terminal:
`java -jar build/libs/mal6raph.jar --config config.json`

In another one:
```bash
docker run \
    --publish=7474:7474 --publish=7687:7687 \
    --volume=`pwd`/neo4j/data:/data \
    --volume=`pwd`/neo4j/logs:/logs \
    neo4j:latest
```

Please, note that you need to configure first your neo4j database (just go to the webpage and enter your new password which is the same that the one in config.json)

Go to http://localhost:8080 and upload your samples.
To find similar functions between a sample and the ones in the db, go to http://localhost:8080/sample/\<sha256Sample\>


## Frontend
Because Mal6raph is only an API, it's kinda useful to have a frontend as well in order to use the analysis done.
You can find one at [here](https://github.com/redmed666/mal6raph-client).

## TODO

* [ ] Implementation of different types of comparison (strings, imports, exports)
* [x] Front end
    * [x] Creation of a front end (it will surely be in another repo)
    * [ ] Possibility to upload FLIRT signatures
    * [ ] Possibility to upload radare2 scripts
* [ ] Creation of YARA rules based on matches