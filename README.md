# URLs Security Scanner

A command-line tool that allows the user to scan one or multiple URLs to get a security score and additional information about the response headers. It supports the following options:

* A single URL
* Multiple URLs separated by spaces
* A file path containing one URL per line

## Usage

To use this tool, run the following command: 
```bash
python urls_scan.py
```

This will prompt the user to enter one of the above options.

The tool also supports passing the URLs as a command-line argument using the --urls option.

```bash
python urls_scan.py --urls "https://urlexample1.com https://example.com"
```

## Output

The script generates two files:
* output_file.csv - A CSV file
* output.json - A JSON file 
