import pandas
import csv

def mean(l):
    if len(l) == 0:
        return 0
    return round(sum(l)/len(l), 2)


def parse_window(window):
    d = []

    connections = [] 
    packets_per_conn = {}
    
    for w in window:
        c = (w[0],w[2],w[1],w[3])
        if c not in connections:
            connections.append(c)
            packets_per_conn[c] = 0

        packets_per_conn[c] += 1

    sources = list(set([c[0] for c in connections]))

    d.append(len(window))
    d.append(len(connections))
    d.append(mean([len(list(filter(lambda c: c[0] == s, connections))) for s in sources]))
    
    # macs = list(set([(w[4], w[0]) for w in window]))
    # print(macs)
    # d.append( max(  same_mac.values() ) if len(macs.values()) > 0 else 0)

    establishing = list(set(map(lambda e: (e[0],e[2],e[1],e[3]), list(filter(lambda w: w[-2] == 1 and w[-3] == 1, window)))))

    d.append(len(establishing))
    d.append(len(connections) - len(establishing))
    d.append(mean(list(map(lambda w: w[-4], window))))
    
    """
    for c in connections:

    for w in window:
        c = (w[0],w[2],w[1],w[3])
    
    """

    d.append(mean(packets_per_conn.values()))

    return d


def check_older(older, newer):
    # return false if older is more than 1 minute older than newer
    return older[-1] >= newer[-1] - 60e9


# dataset = pandas.read_csv('dataset.csv')

# flow = []
# print(dataset)

parsed_dataset = pandas.read_csv('dataset.csv').values

window = []

with open('processed_dataset.csv', 'w') as f:
    writer = csv.writer(f)

    for i, packet in enumerate(parsed_dataset):
        window.append(packet)
        window = list(filter(lambda p: check_older(p, packet), window))
        # f = parse_window(window)
        # flow.append(f)
        writer.writerow(parse_window(window))
        print(f"processed: {format(i/len(parsed_dataset), '.2f')}", end='\r')


