GRADLEW 		= ./gradlew
BACKEND_JAR 	= ./build/libs/mal6raph.jar

all: $(BACKEND_JAR)

$(BACKEND_JAR):
	$(GRADLEW) build && $(GRADLEW) jar

clean:
	rm -rf $(BACKEND_JAR)

