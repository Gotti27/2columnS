import subprocess
# ./collectDataset
p = subprocess.Popen(['ls'], stdout=subprocess.PIPE)

print(p.stdout.readline())




