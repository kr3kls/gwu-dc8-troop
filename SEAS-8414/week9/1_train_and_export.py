# Filename: 1_generate_dga_data.py
import csv
import h2o
import math
import os
import random
import shutil
from h2o.automl import H2OAutoML


# Part 1 - Generate dga_dataset_train.csv
def get_entropy(s):
    p, lns = {}, float(len(s))
    for c in s:
        p[c] = p.get(c, 0) + 1
    return -sum(count/lns * math.log(count/lns, 2) for count in p.values())


# Create sample data
header = ['domain', 'length', 'entropy', 'class']
data = []
# Legitimate domains
legit_domains = ['google', 'facebook', 'amazon', 'github', 'wikipedia', 'microsoft']
for _ in range(250):
    domain = random.choice(legit_domains) + ".com"
    data.append([domain, len(domain), get_entropy(domain), 'legit'])
# DGA domains
for _ in range(250):
    length = random.randint(15, 25)
    domain = ''.join(random.choice('abcdefghijklmnopqrstuvwxyz0123456789') for _ in range(length)) + ".com"
    data.append([domain, len(domain), get_entropy(domain), 'dga'])

with open('dga_dataset_train.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(header)
    writer.writerows(data)

print("dga_dataset_train.csv created successfully.")

# Part 2 - H2O AutoML Execution
h2o.init()
train = h2o.import_file("dga_dataset_train.csv")
x = ['length', 'entropy']  # Features
y = "class"                # Target
train[y] = train[y].asfactor()

aml = H2OAutoML(max_models=20, max_runtime_secs=120, seed=1)
aml.train(x=x, y=y, training_frame=train)

print("H2O AutoML process complete.")
print("Leaderboard:")
print(aml.leaderboard.head())

# Get the best performing model from the leaderboard
best_model = aml.leader

# Download the MOJO artifact and save as DGA_Leader.zip
mojo_path = best_model.download_mojo(path="./models/", get_genmodel_jar=False)
final_path = os.path.join("./models", "DGA_Leader.zip")
shutil.move(mojo_path, final_path)

print(f"Production-ready model saved to: {final_path}")
h2o.cluster().shutdown()
