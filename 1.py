import matplotlib.pyplot as plt
import numpy as np

# بازه های x
x1 = np.linspace(0, 4, 100)
x2 = np.linspace(4, 8, 100)

# نیروی برش V(x)
V1 = np.full_like(x1, 600)  # ثابت در بازه 0 تا 4
V2 = 600 - 600 * (x2 - 4)  # شیب منفی در بازه 4 تا 8

# لنگر خمشی M(x)
M1 = 600 * x1
M2 = -4800 + 3000 * x2 - 300 * x2**2

# رسم نمودار نیروی برش
plt.figure(figsize=(12, 5))
plt.subplot(1, 2, 1)
plt.plot(x1, V1, label="V(x) از 0 تا 4 m")
plt.plot(x2, V2, label="V(x) از 4 تا 8 m")
plt.axhline(0, color='black', linewidth=0.8)
plt.title("نمودار نیروی برش (Shear Force)")
plt.xlabel("طول تیر (m)")
plt.ylabel("نیروی برش (N)")
plt.legend()
plt.grid(True)

# رسم نمودار لنگر خمشی
plt.subplot(1, 2, 2)
plt.plot(x1, M1, label="M(x) از 0 تا 4 m")
plt.plot(x2, M2, label="M(x) از 4 تا 8 m")
plt.axhline(0, color='black', linewidth=0.8)
plt.title("نمودار لنگر خمشی (Bending Moment)")
plt.xlabel("طول تیر (m)")
plt.ylabel("لنگر خمشی (Nm)")
plt.legend()
plt.grid(True)

plt.tight_layout()
plt.show()