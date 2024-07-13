import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing.image import ImageDataGenerator

# Thiết lập đường dẫn đến thư mục chứa dữ liệu test
test_dir = 'E:\Binkit\ẢNH(3=2)-20240621T153805Z-001\ẢNH(3=2)\Test'

# Tạo generator dữ liệu cho tập test
test_datagen = ImageDataGenerator(rescale=1.0/255)
test_generator = test_datagen.flow_from_directory(
        test_dir,
        target_size=(32, 32),
        batch_size=32,
        class_mode='categorical')

# Tải mô hình từ file
model = load_model("E:\Binkit\Model3=0.keras")

# Đánh giá mô hình trên tập test
test_loss, test_acc = model.evaluate(test_generator, steps=100)
#test_loss, test_acc = model.evaluate(test_generator, steps=int(test_generator.samples/test_generator.batch_size))
print('Test accuracy:', test_acc)
