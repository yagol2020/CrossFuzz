## CrossFuzz

CrossFuzz: Cross-Contract Fuzzing for Smart Contract Vulnerability Detection.

### Installation
* OS: Ubuntu 20.04 LTS
* Python 3.8
* Install env and dependencies, follow the instructions below:
* A demo video, showing the build and use process of `CrossFuzz`, can be viewed [here](https://www.bilibili.com/video/BV13u4y1K7Sj).

```shell
sudo apt install python3.8 python3-distutils python3-dev gcc python3-pip python3-venv
git clone https://github.com/yagol2020/CrossFuzz.git
cd CrossFuzz/
python3 -m venv myenv
source myenv/bin/activate
pip3 install wheel
pip3 install -r requirements.txt
solc-select install 0.4.26
solc-select use 0.4.26
mkdir fuzzer/result/
```

* config your solc bin path in `config.py` in `SOLC_BIN_PATH` variable.
* https://github.com/yagol2020/CrossFuzz/blob/ba6182ae25b50cf4864668d7dde8f801fb6c8c96/config.py#L8
    * tips: you can use `which solc` to get the path of your solc bin.

### Usage

* Config `CrossFuzz.py`, you can run a simple when you first run it. Follow the code below and run `test_run()`
  function. This demo will run a simple fuzzer on `examples/T.sol` and generate test cases in `fuzzer/result/res.json`
  directory.

```python
if __name__ == "__main__":
    PYTHON = "python3"  # your python3 path
    FUZZER = "fuzzer/main.py"  # your fuzzer path in this repo
    test_run()
```

* Then, you can see the following output:

```shell
023-11-05 17:52:26.889 | DEBUG    | exam:analysis_depend_contract:31 - 通过分析合约内被写入的状态变量, 发现依赖的合约: Sub
2023-11-05 17:52:26.889 | DEBUG    | exam:analysis_depend_contract:38 - 通过分析合约内函数的参数, 发现依赖的合约: Sub
2023-11-05 17:52:26.890 | DEBUG    | exam:analysis_depend_contract:45 - 通过分析函数的写入变量(局部和状态都算), 发现依赖的合约: Sub
2023-11-05 17:52:26.890 | DEBUG    | exam:analysis_depend_contract:38 - 通过分析合约内函数的参数, 发现依赖的合约: Sub
2023-11-05 17:52:26.890 | DEBUG    | exam:analysis_depend_contract:45 - 通过分析函数的写入变量(局部和状态都算), 发现依赖的合约: Sub
2023-11-05 17:52:26.890 | INFO     | exam:analysis_depend_contract:60 - 依赖合约为: {'Sub'}, 总共有: 3个合约, 需要部署的合约有: 1个
2023-11-05 17:52:26.890 | DEBUG    | exam:analysis_main_contract_constructor:116 - 构造函数参数为: ['_sub contract Sub']
python3 fuzzer/main.py -s ./examples/T.sol -c E --solc v0.4.26 --evm byzantium -t 10 --result fuzzer/result/res.json --cross-contract 1 --open-trans-comp 1 --depend-contracts Sub --constructor-args _sub contract Sub --constraint-solving 1 --max-individual-length 10 --solc-path-cross /usr/local/bin/solc --p-open-cross 80 --cross-init-mode 1 --trans-mode 1
INFO:Main    :Initializing seed to 0.26957612821137267
INFO:Fuzzer  :Fuzzing contract E
INFO:Fuzzer  :依赖合约 Sub deployed at	0x2c5e8a3b3aad9df32339409534e64dfcabcd3a65, 由0xcafebabecafebabecafebabecafebabecafebabe创建
INFO:EVM:encode_values: ['0x2c5e8a3b3aad9df32339409534e64dfcabcd3a65']
INFO:Fuzzer  :主Contract deployed at 0x1c70b9d03f2387195cac4999476f9910bb887994
INFO:Detector:-----------------------------------------------------
INFO:Detector:        !!! Unchecked return value detected !!!         
INFO:Detector:-----------------------------------------------------
INFO:Detector:SWC-ID:   104
INFO:Detector:Severity: Medium
INFO:Detector:-----------------------------------------------------
INFO:Detector:Source code line:
INFO:Detector:-----------------------------------------------------
INFO:Detector:./examples/T.sol:43:1
INFO:Detector:sub.addBalances(_addr, _amount)
INFO:Detector:-----------------------------------------------------
INFO:Detector:Transaction sequence:
INFO:Detector:-----------------------------------------------------
INFO:Detector:Transaction - addBalance(address,uint256):
INFO:Detector:-----------------------------------------------------
INFO:Detector:From:      0x2c5e8a3b3aad9df32339409534e64dfcabcd3a65
INFO:Detector:To:        0x1c70b9d03f2387195cac4999476f9910bb887994
INFO:Detector:Value:     0 Wei
INFO:Detector:Gas Limit: 4500000
INFO:Detector:Input:     0x21e5383a000000000000000000000000cafebabe
INFO:Detector:           cafebabecafebabecafebabecafebabee04f2350f2
INFO:Detector:           28cfac00dbc7c929cb896d982c1c1d525fa6e76006
INFO:Detector:           1bf7c21ee7b6
INFO:Detector:-----------------------------------------------------
INFO:Analysis:Generation number 0 	 Code coverage: 86.28% (610/707) 	 Branch coverage: 78.26% (36/46) 	 Transactions: 18 (16 unique, 0 from cross)   	 Time: 0.04033660888671875
INFO:Analysis:Generation number 1 	 Code coverage: 95.19% (673/707) 	 Branch coverage: 84.78% (39/46) 	 Transactions: 61 (31 unique, 5 from cross)   	 Time: 0.1703794002532959

......

INFO:Analysis:Generation number 16 	 Code coverage: 97.45% (689/707) 	 Branch coverage: 93.48% (43/46) 	 Transactions: 3336 (256 unique, 80 from cross)   	 Time: 9.013849258422852
INFO:Analysis:Generation number 17 	 Code coverage: 97.45% (689/707) 	 Branch coverage: 93.48% (43/46) 	 Transactions: 3702 (271 unique, 85 from cross)   	 Time: 10.033984184265137
INFO:Analysis:-----------------------------------------------------
INFO:Analysis:Number of generations: 	 17
INFO:Analysis:Number of transactions: 	 3702 (271 unique)
INFO:Analysis:Transactions per second: 	 368
INFO:Analysis:Total code coverage: 	 97.45% (689/707)
INFO:Analysis:Total branch coverage: 	 93.48% (43/46)
INFO:Analysis:Total execution time: 	 10.05 seconds
INFO:Analysis:Total memory consumption: 	 102.43 MB
```

* You can see the result in `fuzzer/result/res.json`, part of the result is as follows:

```json
{
  "E": {
    "errors": {},
    "generations": [],
    "transactions": {
      "total": 3702,
      "per_second": 368.20883163556454
    },
    "code_coverage": {
      "percentage": 97.45403111739745,
      "covered": 689,
      "total": 707,
      "covered_with_children": 689,
      "total_with_children": 0
    },
    "branch_coverage": {
      "percentage": 93.47826086956522,
      "covered": 43,
      "total": 46
    },
    "execution_time": 10.0540771484375,
    "memory_consumption": 102.43359375,
    "address_under_test": "0x1c70b9d03f2387195cac4999476f9910bb887994",
    "seed": 0.26957612821137267
  }
}
```

#### Test your contract by command line

* Config `CrossFuzz.py` to command line mode

```python
if __name__ == "__main__":
    PYTHON = "python3"  # your python3 path
    FUZZER = "fuzzer/main.py"  # your fuzzer path in this repo
    cli()
```

* Suppose the smart contract file you want to test is `examples/T.sol`, the name of the contract under tested is `E`,
  the version of solc compiler is `0.4.26`, the max length of transaction sequence is `5`, fuzz time is `60` second,
  the binary path of solc compiler is `/usr/local/bin/solc`.
  Then you can run the following command to test
  it:

```shell
python CrossFuzz.py examples/T.sol E 0.4.26 5 60 ./res.json /usr/local/bin/solc auto 0
```

* You can manually set the constructor arguments of the contract under tested by changing the last parameter of the
  command above. Specifically, you can set the last parameter to the path of a json file, which contains the constructor
  parameters of the contract under tested. The format of the json file is as follows:

```json
{
  "_sub": {
    "type": "contract",
    "value": "Sub"
  },
  "_p": {
    "type": "uint256",
    "value": 12
  }
}
```

Then you can run the following command to test it with the constructor arguments:

```shell
python CrossFuzz.py examples/T.sol E 0.4.26 5 60 ./res.json /usr/local/bin/solc examples/p.json 0
```

* CrossFuzz generate transaction sequences without duplicate transactions. If you want to generate transaction
  sequences with duplicate transactions, you can run the following command (by changing the last parameter to `1`):

```shell
python CrossFuzz.py examples/T.sol E 0.4.26 5 60 ./res.json /usr/local/bin/solc auto 1
```

* After the fuzzing process is finished, you can see the result in `res.json` file.

### Links and copyright

* This repo is based on [ConFuzzius](https://github.com/christoftorres/ConFuzzius). `ConFuzzius` is licensed under the
  MIT License - see the `LICENSE` file for details.

### Demo

[![Demo](https://github.com/yagol2020/CrossFuzz/blob/dev/demo_video/demo.png)](https://www.bilibili.com/video/BV13u4y1K7Sj "Demo")
