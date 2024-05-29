import pandas as pd
import numpy as np
import matplotlib.pyplot as plt

## Read Excel file into a pandas DataFrame
df = pd.read_excel(r"C:\Users\vagmi\Documents\Quantum ARP SPOOF DETECTION\arp_spoof_log.xlsx")

# Attack types
attack_types = ['Eavesdropping', 'MAC Flooding', 'Session Hijacking', 'Unknown']

# Generate random data
data = {
    'Attack Type': np.random.choice(attack_types, size=100),
    'Mean Severity Score': np.random.randint(0, 101, size=100),
    'Detection Rate Score': np.random.randint(0, 101, size=100)
}


# Create DataFrame
df = pd.DataFrame(data)

# Plotting
plt.figure(figsize=(10, 6))

# Mean Severity Score plot
plt.subplot(2, 1, 1)
for attack_type in attack_types:
    plt.bar(attack_type, df[df['Attack Type'] == attack_type]['Mean Severity Score'].mean(), label=attack_type)
plt.ylim(0, 100)
plt.ylabel('Mean Severity Score')
plt.title('Mean Severity Score by Attack Type')
plt.legend()

# Detection Rate Score plot
plt.subplot(2, 1, 2)
for attack_type in attack_types:
    plt.bar(attack_type, df[df['Attack Type'] == attack_type]['Detection Rate Score'].mean(), label=attack_type)
plt.ylim(0, 100)
plt.ylabel('Detection Rate Score')
plt.title('Detection Rate Score by Attack Type')
plt.legend()

plt.tight_layout()
plt.show()
