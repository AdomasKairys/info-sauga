#!/bin/bash
mvn clean install
mvn dependency:copy-dependencies
java -cp "target/demo-1.0.jar;target/dependency/*" com.example.sauga
