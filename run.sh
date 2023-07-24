#!/bin/bash

# Run configs
JAVA=java

function display_usage() {
    echo "Usage: QtRE run.sh [-h] -p qtre_path -c config_path [-g ghidra_path] [--analyze-connect] [--analyze-meta]"
    echo "Example: ./run.sh -p QtRE-1.0.0.jar -c env.json --analyze-connect --analyze-meta"
    echo "Argument descriptions: "
    echo "  -h, --help: Display this help message."
    echo "  -p, --qtre-path: Path to the compiled QtRE Jar executable."
    echo "  -c, --config-path: Path to the json configuration file."
    echo "  -g, --ghidra-path: Path to Ghidra jar library (default: ./lib/ghidra.jar)."
    echo "  --analyze-connect: Enable analysis on Qt Connect."
    echo "  --analyze-meta: Enable analysis on Qt Metadata."
    echo ""
}

# Parameters
QTRE_JAR_PATH=QtRE-1.0.0.jar

ENV_JSON_PATH=env.json

GHIDRA_JAR_PATH=./lib/ghidra.jar

ANALYZE_QT_CONNECT=0

ANALYZE_QT_META=0

if [ $# -lt 1 ]; then
    display_usage
    exit 0
fi

# Parse command-line options
while [[ $# -gt 0 ]]; do
    key="$1"

    case $key in
        -h|--help)
            display_usage
            exit 0
            ;;
        -p|--qtre-path)
            QTRE_JAR_PATH="$2"
            shift # past argument
            ;;
        -c|--config-path)
            ENV_JSON_PATH="$2"
            shift # past argument
            ;;
        -g|--ghidra-path)
            GHIDRA_JAR_PATH="$2"
            shift # past argument
            ;;
        --analyze-connect)
            ANALYZE_QT_CONNECT=1
            ;;
        --analyze-meta)
            ANALYZE_QT_META=1
            ;;
        *)
            # Unknown option
            echo "Error: Unknown option $key"
            display_usage
            exit 1
            ;;
    esac
    shift # past argument or value
done


# RUN
${JAVA} -cp ${QTRE_JAR_PATH}:${GHIDRA_JAR_PATH} Main.Main ${ENV_JSON_PATH} ${ANALYZE_QT_CONNECT} ${ANALYZE_QT_META}
