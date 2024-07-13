import tensorflow as tf
from tensorflow.keras.preprocessing.image import ImageDataGenerator
import numpy as np
import matplotlib.pyplot as plt

# Thiết lập các đường dẫn đến các thư mục chứa dữ liệu
train_dir = 'E:\Binkit\ẢNH(3=0)-20240621T154725Z-001\\ẢNH(3=0)\\Train'
validation_dir = 'E:\\Binkit\\ẢNH(3=0)-20240621T154725Z-001\\ẢNH(3=0)\\Valid'

# Kích thước ảnh đầu vào
input_shape = (32, 32, 3)  # 3 kênh màu (RGB)

# Tạo các ImageDataGenerator cho dữ liệu train, validation và test
train_datagen = ImageDataGenerator(rescale=1.0/255)
validation_datagen = ImageDataGenerator(rescale=1.0/255)
test_datagen = ImageDataGenerator(rescale=1.0/255)

train_generator = train_datagen.flow_from_directory(
        train_dir,
        target_size=(32, 32),
        batch_size=32,
        class_mode='categorical')

validation_generator = validation_datagen.flow_from_directory(
        validation_dir,
        target_size=(32, 32),
        batch_size=32,
        class_mode='categorical')


# Xây dựng mô hình CNN
model = tf.keras.models.Sequential([
    tf.keras.layers.Conv2D(64, (2, 2), activation='relu', input_shape=input_shape),
    tf.keras.layers.MaxPooling2D((2, 2)),
    tf.keras.layers.Conv2D(64, (2, 2), activation='relu'),
    tf.keras.layers.MaxPooling2D((2, 2)),
    tf.keras.layers.Flatten(),
    tf.keras.layers.Dropout(0.5),

    tf.keras.layers.Dense(512, activation='relu'),
    tf.keras.layers.Dense(2, activation='sigmoid')  
])

# Compile mô hình
model.compile(optimizer='adam',
              loss='categorical_crossentropy',
              metrics=['accuracy'])

# Huấn luyện mô hình
history = model.fit(
      train_generator,
      steps_per_epoch=20,
      epochs=50,
      verbose=1,
      validation_data=validation_generator,
      validation_steps=3)

# Lưu mô hình đã huấn luyện vào file
model.save("E:\Binkit\Model3=0.keras")


