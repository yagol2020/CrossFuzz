pragma solidity 0.4.26;


contract Sub {
    mapping(address => uint) public balances;

    function addBalances(address _addr, uint _amount) public {
        balances[_addr] += _amount;
    }

    function checkBalance(address _addr) public view returns (uint) {
        return balances[_addr];
    }
}

contract Child {
    uint inner;
}

contract E is Child {
    Sub sub;
    uint count;
    bool flag;

    function E(Sub _sub) public {
        sub = Sub(_sub);
    }

    function setSub(Sub _sub) public {
        sub = Sub(_sub);
    }

    function setCount(uint _count) public {
        count = _count;
    }

    modifier minBalance {
        require(sub.checkBalance(msg.sender) >= 1 ether);
        _;
    }

    function addBalance(address _addr, uint _amount) public {
        sub.addBalances(_addr, _amount);
        count += 1;
    }

    function getFlag() public returns (bool) {
        return flag;
    }

    function setFlag(bool _flag) public {
        flag = _flag;
    }

    function getInner() public returns (uint) {
        return inner;
    }

    function withdraw(address _addr, uint _amount) public minBalance {
        if (count > 50) {
            revert();
        } else {
            count += 2;
        }
        _addr.transfer(_amount);
    }

}