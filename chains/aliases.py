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


def get_aliases():
    return aliases_btc.keys()


def get_alias_address(chain, alias):
    if not alias:
        return
    if chain == "BNB":
        return aliases_bnb[alias]
    if chain == "BTC":
        return aliases_btc[alias]
    raise Exception("Address for alias not found, chain not supported")


def get_bnb_address(chain, addr):
    if chain == "BNB":
        return addr
    if chain == "BTC":
        for alias, btc_addr in aliases_btc.items():
            if addr == btc_addr:
                return aliases_bnb[alias]
    return addr


def get_alias(chain, addr):
    if chain == "BNB":
        aliases = aliases_bnb
    if chain == "BTC":
        aliases = aliases_btc
    for name, alias_addr in aliases.items():
        if alias_addr == addr:
            return name
    return addr
