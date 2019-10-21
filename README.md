# TransparentLoadBalancer
CS436 Software Defined Networks

OpenFLow & Mininet

Red and Blue clients can ping the service IP, which transparently balances the load to red and blue servers respectively.
The balancing mechanism is random choosing, and rules should be kept for 10 seconds after becoming idle

Topology initialized with
  'sudo mn --topo single,8 --mac --switch ovsk --controller remote'
