import numpy as np

A = np.arange(95,99).reshape(2,2)
print(A)

A = np.pad(A,pad_width=((3,2),(2,3)), constant_values = (0,1))
print(A)