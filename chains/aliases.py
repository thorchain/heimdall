aliases_btc = {
    "MASTER": "bcrt1qj08ys4ct2hzzc2hcz6h2hgrvlmsjynawhcf2xa",
    "CONTRIB": "bcrt1qzupk5lmc84r2dh738a9g3zscavannjy3084p2x",
    "USER-1": "bcrt1qqqnde7kqe5sf96j6zf8jpzwr44dh4gkd3ehaqh",
    "STAKER-1": "bcrt1q0s4mg25tu6termrk8egltfyme4q7sg3h8kkydt",
    "STAKER-2": "bcrt1qjw8h4l3dtz5xxc7uyh5ys70qkezspgfutyswxm",
    "VAULT": "",
}

aliases_bnb = {
    "MASTER": "tbnb1ht7v08hv2lhtmk8y7szl2hjexqryc3hcldlztl",
    "CONTRIB": "tbnb1lltanv67yztkpt5czw4ajsmg94dlqnnhrq7zqm",
    "USER-1": "tbnb157dxmw9jz5emuf0apj4d6p3ee42ck0uwksxfff",
    "STAKER-1": "tbnb1mkymsmnqenxthlmaa9f60kd6wgr9yjy9h5mz6q",
    "STAKER-2": "tbnb189az9plcke2c00vns0zfmllfpfdw67dtv25kgx",
    "VAULT": "tbnb14jg77k8nwcz577zwd2gvdnpe2yy46j0hkvdvlg",
}

aliases_eth = {
    "MASTER": "0x3fd2d4ce97b082d4bce3f9fee2a3d60668d2f473",
    "CONTRIB": "0x970e8128ab834e8eac17ab8e3812f010678cf791",
    "USER-1": "0xf6da288748ec4c77642f6c5543717539b3ae001b",
    "STAKER-1": "0xfabb9cc6ec839b1214bb11c53377a56a6ed81762",
    "STAKER-2": "0x1f30a82340f08177aba70e6f48054917c74d7d38",
    "VAULT": "",
}

aliases_thor = {
    "MASTER": "tthor1nrsk6f4kalwwrqqyrfmxzl96hyjhe96t4gmvp2",
    "CONTRIB": "tthor1m8prd4pvqe5p3cu7tu82pn50a5f9xzxzetc35t",
    "USER-1": "tthor1gll3y5vr2q05zlyuuuzr0d77gc0qmn2jhjc77w",
    "STAKER-1": "tthor1n8a9fzxk09pqxgklx4dfrfnj4nlsgw8mamggsy",
    "STAKER-2": "tthor14p96zkwe4hffj67lq27dprdwlvjzkufpv02yfq",
    "VAULT": "tthor1v5lj0xlnutn745wtduefx2gnvh0namlpnqv7jp",
    "RESERVE": "tthor1xuuv8fqrrpt7vlna7p7evsg9fnvlje3x6kdgem",
    "BOND": "tthor1u2y3229432q0z4ul56k3keu4leleuwwcsp9s0k",
}


def get_aliases():
    return aliases_btc.keys()


def get_address_prefix(chain):
    if chain == "BNB":
        return "tbnb"
    if chain == "BTC":
        return "bc"
    if chain == "THOR":
        return "thor"
    raise Exception(f"Address prefix not found, chain not supported ({chain})")


def get_alias_address(chain, alias):
    if not alias:
        return
    if chain == "BNB":
        return aliases_bnb[alias]
    if chain == "BTC":
        return aliases_btc[alias]
    if chain == "ETH":
        return aliases_eth[alias]
    if chain == "THOR":
        return aliases_thor[alias]
    raise Exception(f"Address for alias not found, chain not supported ({chain})")


def get_alias(chain, addr):
    if chain == "BNB":
        aliases = aliases_bnb
    if chain == "BTC":
        aliases = aliases_btc
    if chain == "ETH":
        aliases = aliases_eth
    if chain == "THOR":
        aliases = aliases_thor
    for name, alias_addr in aliases.items():
        if alias_addr == addr:
            return name
    return addr
