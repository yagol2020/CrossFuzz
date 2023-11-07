#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import random

from copy import deepcopy, copy
from eth_abi import encode_abi
from eth_abi.exceptions import EncodingTypeError, ValueOutOfBounds, ParseError

from fuzzer.utils import settings
from fuzzer.utils.utils import initialize_logger


class Individual():
    def __init__(self, generator, other_generators=None):
        self.logger = initialize_logger("Individual")
        self.chromosome = []
        self.solution = []
        self.generator = generator
        self.other_generators = other_generators if other_generators is not None else []

    @property
    def hash(self):
        if not self.solution:
            self.solution = self.decode()
        return str(hash(str([tx for tx in self.solution])))

    def append_other(self):
        chosen_generator = random.choice(self.other_generators + [self.generator])
        self.chromosome.extend(chosen_generator.generate_random_individual())
        self.chromosome = random.sample(self.chromosome, len(self.chromosome))
        self.solution = self.decode()

    def init(self, chromosome=None, single=False, func_hash=None, func_args_types=None, default_value=False, no_cross=False):
        if not chromosome:
            if settings.TRANS_MODE == "origin" or no_cross:
                self.chromosome = self.generator.generate_random_individual(func_hash, func_args_types, default_value)
            elif settings.TRANS_MODE == "cross" and single is False:
                if len(settings.TRANS_CROSS_BAD_INDVS) > 0:
                    self.chromosome = self.generator.generate_individual_by_cross()
                    settings.CROSS_TRANS_EXEC_COUNT += 1
            elif settings.TRANS_MODE == "cross" and single:
                self.chromosome = self.generator.generate_random_individual(func_hash, func_args_types, default_value)
        else:
            self.chromosome = chromosome
        self.solution = self.decode()
        return self

    def create_cross_individual(self):
        pass

    def clone(self):
        indv = self.__class__(generator=self.generator, other_generators=self.other_generators)
        indv.init(chromosome=deepcopy(self.chromosome))
        return indv

    def decode(self):
        solution = []
        for i in range(len(self.chromosome)):
            transaction = {}
            transaction["from"] = copy(self.chromosome[i]["account"])
            transaction["to"] = copy(self.chromosome[i]["contract"])
            transaction["value"] = copy(self.chromosome[i]["amount"])
            transaction["gaslimit"] = copy(self.chromosome[i]["gaslimit"])
            if transaction["to"] == self.generator.contract:
                transaction["data"] = self.get_transaction_data_from_chromosome(i, self.generator)
            else:
                for o_g in self.other_generators:
                    if transaction["to"] == o_g.contract:
                        transaction["data"] = self.get_transaction_data_from_chromosome(i, o_g)
                        break
            block = {}
            if "timestamp" in self.chromosome[i] and self.chromosome[i]["timestamp"] is not None:
                block["timestamp"] = copy(self.chromosome[i]["timestamp"])
            if "blocknumber" in self.chromosome[i] and self.chromosome[i]["blocknumber"] is not None:
                block["blocknumber"] = copy(self.chromosome[i]["blocknumber"])

            global_state = {}
            if "balance" in self.chromosome[i] and self.chromosome[i]["balance"] is not None:
                global_state["balance"] = copy(self.chromosome[i]["balance"])
            if "call_return" in self.chromosome[i] and self.chromosome[i]["call_return"] is not None \
                    and len(self.chromosome[i]["call_return"]) > 0:
                global_state["call_return"] = copy(self.chromosome[i]["call_return"])
            if "extcodesize" in self.chromosome[i] and self.chromosome[i]["extcodesize"] is not None \
                    and len(self.chromosome[i]["extcodesize"]) > 0:
                global_state["extcodesize"] = copy(self.chromosome[i]["extcodesize"])

            environment = {}
            if "returndatasize" in self.chromosome[i] and self.chromosome[i]["returndatasize"] is not None:
                environment["returndatasize"] = copy(self.chromosome[i]["returndatasize"])

            input = {"transaction": transaction, "block": block, "global_state": global_state, "environment": environment}
            solution.append(input)
        return solution

    def get_transaction_data_from_chromosome(self, chromosome_index, generator):
        data = ""
        arguments = []
        function = None
        for j in range(len(self.chromosome[chromosome_index]["arguments"])):
            if self.chromosome[chromosome_index]["arguments"][j] == "fallback":
                function = "fallback"
                data += random.choice(["", "00000000"])
            elif self.chromosome[chromosome_index]["arguments"][j] == "constructor":
                function = "constructor"
                data += generator.bytecode
            elif not type(self.chromosome[chromosome_index]["arguments"][j]) is bytearray and \
                    not type(self.chromosome[chromosome_index]["arguments"][j]) is list and \
                    self.chromosome[chromosome_index]["arguments"][j] in generator.interface:
                function = self.chromosome[chromosome_index]["arguments"][j]
                data += self.chromosome[chromosome_index]["arguments"][j]
            else:
                arguments.append(self.chromosome[chromosome_index]["arguments"][j])
        try:
            argument_types = [argument_type.replace(" storage", "").replace(" memory", "") for argument_type in generator.interface[function]]
            data += encode_abi(argument_types, arguments).hex()
        except Exception as e:
            self.logger.error("%s", e)
            self.logger.error("%s: %s -> %s", function, generator.interface[function], arguments)
            sys.exit(-6)
        return data
