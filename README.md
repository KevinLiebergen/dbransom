# Database Ransom(ware)

This repository contains the clustering code and clustering results for our NDSS 2025 paper:

> All your (data)base are belong to us: Characterizing Database Ransom(ware) Attacks.<br>
Kevin van Liebergen, Gibran Gomez, Srdjan Matic, and Juan Caballero.<br>
In Proceedings of the Network and Distributed Systems Security Symposium.<br>
Februrary 2025.<br>
DOI: 10.14722/ndss.2025.241887

If you use the contents of this repository, please cite the above paper.

---

## Table of Contents
- [Data](#data)
- [Code](#code)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)

---

## Data

The *data* folder contains two JSONL files (one JSON object per line).<br>
- `clustering.jsonl` contains the paper's clustering results with 32 groups (one per line in the file) that run 91 campaigns. Each group cluster has properties such as the number of compromised servers, the lifetime, the revenue, and the indicators used.
- `leakix.jsonl` is a sample input file with a few [LeakIX](https://leakix.net/) events to test the code.

## Code

The clustering code is in the *scripts* folder.
The main file is `leakix_stats.py`, which performs the following:

1. Cluster the database ransomware notes in the LeakIX events by analyzing the similarity of their content.
2. Merge clusters that reuse Indicators of Compromise (IOCs).

The third step in the paper, i.e., merging clusters that are in the same Bitcoin multi-input cluster, is not implemented in this code as it requires installing a separate Bitcoin analysis platform like [WatchYourBack](https://github.com/cybersec-code/watchyourback)

## Installation

Follow these steps to set up the environment and install the necessary dependencies:

### 1. Clone the repository
First, clone the repository to your local machine:

```bash
git clone https://github.com/kevinliebergen/dbransom.git
cd dbransom
```

### 2. Set up the Conda environment
Make sure you have Conda installed. If you don’t have it, you can download it from [Conda's official site](https://docs.conda.io/en/latest/miniconda.html).

Create the environment using the provided `environment.yml` file:

```bash
conda env create -f environment.yml
```

Activate the environment:

```bash
conda activate dbransom
```

---

## Usage

Once the environment is set up, you can run the main script with the following command:

```bash
python scripts/leakix_stats.py -i data/leakix.jsonl -cs -t 6 -ci
```

### Command-Line Arguments
- **`-i`**: Path to the input JSONL file. This file contains the events from the LeakIX Internet-wide Scanner (e.g., `leakix.jsonl`).
- **`-cs`**: Cluster by similarity.
- **`-t`**: Threshold value used in note similarity clustering (e.g., `6`).
- **`-ci`**: Cluster by IOC.

**Note:** Ensure that the test input file (`data/leakix.jsonl`)
 is in the current directory or provide its full path.

The test input file contains 7 LeakIX events, 
which are first grouped into 4 note similarity clusters and 
then merged into 2 group clusters through IOC reuse.

---

## License

This project is licensed under the [MIT License](LICENSE).

---

