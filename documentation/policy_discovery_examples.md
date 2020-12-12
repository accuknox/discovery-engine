# The intersection of matched labels

<center><img src=./resources/example1.png></center>

Let's assume that there are three pods and two connections between them as shown in the above figure. From the network logs from it, the knoxAutoPolicy does not discover the two distinct network policies; [Pod A -> Pod C] and [Pod A -> Pod C]. 

Instead, since Pod A and Pod B have the intersection of the labels, which is 'group=alice', the knoxAutoPolicy discovers and generates a network policy that has the selector with matchLabels 'group=alice'. Finally, we can get one network policy that covers two distinct network flows [group=alice -> Pod C].

# The aggregation of ToPorts rules per the same destination

<center><img src=./resources/example2.png></center>

Similar to the previous case, we can merge the multiple ToPorts rules per each same destination. Let's assume that there are the source and destination pods and three different flows as shown in the above figure. In this case, the knoxAutoPolicy does not generate three different network policies per each ToPorts rule.

More efficiently, the knoxAutoPolicy discovers one network policy and has one matchLabel rule and three ToPorts rules; port numbers are 443, 8080, and 80. From this merge, it can be enabled to produce a minimum network policy set covering maximum network flows.

# The trace of the outdated network policy

<center><img src=./resources/example3.png></center>

Since the knoxAutoPolicy can do the discovery job at the time intervals, there could be some overlappings. For example, as shown in the above figure, let's assume we discovered policy A and B at the time t1 and t2 respectively. 

However, policy B has the same ToCIDRs rule as policy A does but a different toPorts rule. In this case, the knoxAutoPolicy updates policy B by merging the ToPorts rule to the latest one, and then it marks policy A as outdated and puts the relevant latest policy name. Thus, users can retrieve only the latest network policies from the database.
