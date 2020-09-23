# Live-20
### Live plugin fork compatible with VPP 20.05+

## Main features
* Compliance with VPP [new build system](https://fdio-vpp.readthedocs.io/en/latest/gettingstarted/developers/buildsystem/cmakeandninja.html) leveraging CMake and Ninja.
* Patches to non rollover-safe code causing packet drops.
* Patches to non thread-safe code in flow handling causing race conditions in flow initialization and duplicated packets.
* Revised window update algorithm in B variant.
* Stability fixes.
* Multithreading support.

## Installation

### Install Live on _tail_ (ingress) node
1) Copy `live` directory to `vpp/src/plugins`.
1) Copy `sr.h` to `vpp/src/vnet/srv6` overwriting original file.
1) Copy `sr_policy_rewrite.c` to `vpp/src/vnet/srv6` overwriting original file.
  
### Install Live on _head_ (egress) node - variant _A_
1) Copy `srv6-livea` directory to `vpp/src/plugins`.
1) Copy `sr.h` to `vpp/src/vnet/srv6` overwriting original file.
1) Copy `sr_localsid.c` to `vpp/src/vnet/srv6` overwriting original file.

### Install Live on _head_ (egress) node - variant _B_
1) Copy `srv6-liveb` directory to `vpp/src/plugins`.
1) Copy `sr.h` to `vpp/src/vnet/srv6` overwriting original file.
1) Copy `sr_localsid.c` to `vpp/src/vnet/srv6` overwriting original file.

## Configuration

### Enable Live LocalSID on egress node

* Define a LocalSID `a` in node `e2` that decapsulates traffic and forwards it on interface `if_out` towards address `b::1`:

    `sr localsid address e2::a behavior live.a.dx6 nh b::1 oif if_out`


### Duplicate traffic from ingress node
1) Encapsulate traffic associated to this policy with address `e1::`:

    `set sr encaps source addr e1::`

2) Create a policy `e1::999:a` that encapsulates the traffic and forwards it towards transit node `c1` and afterwards to final decapsulating node `e2`:

    `sr policy add bsid e1::999:a next c1:: next e2::a encap`

3) Add to the previously created policy a segment list with the additional path passing through `c2` where to send duplicated packets:

    `sr policy mod bsid e1::999:a add sl next c2:: next e2::a`

4) Mark the policy as a Live policy:

    `live sr policy bsid e1::999:a`

5) Steer the traffic with destination address `b::/64` towards the Live policy:

    `sr steer l3 b::/64 via bsid a::999:a`