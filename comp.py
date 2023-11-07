from config import *
from queue import Queue
from slither import Slither
from slither.core.declarations import Contract
from typing import Tuple, List
from slither.core.expressions import TypeConversion, Identifier, AssignmentOperation
from slither.core.solidity_types import UserDefinedType

logger = get_logger()


@logger.catch()
def analysis_depend_contract(file_path: str, _contract_name: str, _solc_version: str, _solc_path) -> (
        Tuple)[List, Slither]:
    res = set()  # 需要被部署的合约
    sl = Slither(file_path, solc=_solc_path)
    to_be_deep_analysis = Queue()  # 这个列表里的每一个都需要分析
    to_be_deep_analysis.put(_contract_name)
    while not to_be_deep_analysis.empty():
        c = to_be_deep_analysis.get()
        contract = sl.get_contract_from_name(c)
        if len(contract) != 1:
            logger.warning("理论上, 根据合约名字, 只能找到一个合约")
            return [], sl
        contract = contract[0]
        # 1. 分析被写入的状态变量
        for v in contract.all_state_variables_written:
            if not v.initialized and isinstance(v.type, UserDefinedType) and hasattr(v.type, "type") and isinstance(
                    v.type.type, Contract):
                res.add(v.type.type.name)
                logger.debug("通过分析合约内被写入的状态变量, 发现依赖的合约: {}".format(v.type.type.name))
        for f in contract.functions:
            # 2. 分析合约内函数的参数
            for p in f.parameters:
                if isinstance(p.type, UserDefinedType) and hasattr(p.type, "type") and isinstance(p.type.type,
                                                                                                  Contract):
                    res.add(p.type.type.name)
                    logger.debug("通过分析合约内函数的参数, 发现依赖的合约: {}".format(p.type.type.name))
            # 3. 分析函数的写入变量, 如果是合约类型, 那么也需要部署
            for v in f.variables_written:
                if hasattr(v, "type") and isinstance(v.type, UserDefinedType) and hasattr(v.type,
                                                                                          "type") and isinstance(
                    v.type.type, Contract):
                    res.add(v.type.type.name)
                    logger.debug("通过分析函数的写入变量(局部和状态都算), 发现依赖的合约: {}".format(v.type.type.name))
        # 3. 分析合约内的继承关系, 添加到待分析队列中
        for inherit in contract.inheritance:
            if inherit.name not in res:
                to_be_deep_analysis.put(inherit.name)
    if _contract_name in res:
        logger.debug("主合约被分析到了依赖合约中, 需要移除")
        res.remove(_contract_name)
    # 4. 判断依赖合约的bytecode, 移除为空的合约
    compilation_unit = sl.compilation_units[0].crytic_compile_compilation_unit
    for depend_c in res.copy():
        if compilation_unit.bytecode_runtime(depend_c) == "" or compilation_unit.bytecode_runtime(depend_c) == "":
            logger.debug(f"依赖合约 {depend_c}的bytecode为空, 已移除")
            res.remove(depend_c)

    logger.info("依赖合约为: " + str(res) + ", 总共有: " + str(len(sl.contracts)) + "个合约, 需要部署的合约有: " + str(
        len(res)) + "个")
    return list(res), sl


def analysis_main_contract_constructor(file_path: str, _contract_name: str, sl: Slither = None):
    if sl is None:
        sl = Slither(file_path, solc=SOLC_BIN_PATH)
    contract = sl.get_contract_from_name(_contract_name)
    assert len(contract) == 1, "理论上, 根据合约名字, 只能找到一个合约"
    contract = contract[0]
    # 1. 分析合约内的构造函数
    constructor = contract.constructor
    if constructor is None:  # 没有构造函数
        return []
    # 1. 获得构造函数的所有参数, 若name不为address, 则为其设置YA_DO_NOT_KNOW, 其他的暂时初始化为一个list, list保存数据流
    res = []
    for p in constructor.parameters:
        if (hasattr(p.type, "type") and hasattr(p.type.type, "kind") and p.type.type.kind == "contract"):
            res.append((p.name, "contract", p.name, [p.type.type.name]))
        elif hasattr(p.type, "name"):
            if p.type.name != "address":
                res.append((p.name, p.type.name, "YA_DO_NOT_KNOW", ["YA_DO_NOT_KNOW"]))
            else:
                res.append((p.name, p.type.name, [p.name], []))
        else:  # 可能是数组
            return None
    # 2. 分析构造函数内部数据流流动
    for exps in constructor.expressions:  # 解析构造函数内部的表达式, 分析哪些数据流向了状态变量
        if isinstance(exps, AssignmentOperation):
            exps_right = exps.expression_right
            exps_left = exps.expression_left
            if isinstance(exps_right, Identifier) and isinstance(exps_left, Identifier):
                for cst_param in res:
                    if isinstance(cst_param[2], list) and exps_right.value.name in cst_param[2]:
                        cst_param[2].append(exps_left.value.name)
            elif isinstance(exps_right, TypeConversion) and isinstance(exps_left, Identifier):
                param_name, param_map_contract_name = extract_param_contract_map(exps_right)
                if param_name is not None and param_map_contract_name is not None:
                    for cst_param in res:
                        if isinstance(cst_param[2], list) and param_name in cst_param[2]:
                            cst_param[3].append(param_map_contract_name)
        elif isinstance(exps, TypeConversion):
            param_name, param_map_contract_name = extract_param_contract_map(exps)
            if param_name is not None and param_map_contract_name is not None:
                for cst_param in res:
                    if isinstance(cst_param[2], list) and param_name in cst_param[2]:
                        cst_param[3].append(param_map_contract_name)
    # 转换res
    ret = []
    for p_name, p_type, _, p_value in res:
        if p_type == "address" and len(p_value) == 0:
            p_value = ["YA_DO_NOT_KNOW"]
        p_value = list(set(p_value))
        assert len(p_value) == 1, "理论上, 每个参数只能有一个预期值"
        ret.append(f"{p_name} {p_type} {p_value[0]}")
    logger.debug("构造函数参数为: " + str(ret))
    return ret


def extract_param_contract_map(exps: TypeConversion):
    inner_exp = exps.expression
    if isinstance(inner_exp, Identifier) \
            and isinstance(exps.type, UserDefinedType) \
            and hasattr(exps.type, "type") \
            and isinstance(exps.type.type, Contract):
        return inner_exp.value.name, exps.type.type.name
    else:
        return None, None
