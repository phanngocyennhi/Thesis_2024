import cv2
import numpy as np
import re
import os

def vector_to_image(vector, output_image_path, image_shape):
    # Chia vector thành các ma trận dựa trên image_shape
    channels = image_shape[2]
    image_channels = np.split(vector, channels)
    
    # Chuyển đổi mỗi ma trận thành ảnh có kích thước image_shape[0] x image_shape[1]
    image = np.stack([channel.reshape((image_shape[0], image_shape[1])) for channel in image_channels], axis=-1)
    
    # Nếu số kênh ít hơn 3, thêm kênh bổ sung với giá trị 0
    if channels < 3:
        zero_channel = np.zeros((image_shape[0], image_shape[1], 3 - channels), dtype=image.dtype)
        image = np.concatenate((image, zero_channel), axis=-1)
    
    # Chuyển đổi kiểu dữ liệu sang uint8
    image = image.astype(np.uint8)
    
    # Lưu mảng thành ảnh
    cv2.imwrite(output_image_path, image)

def read_vector_from_txt(txt_file):
    with open(txt_file, 'r') as file:
        content = file.readlines()
        vectors = []
        for line in content:
            # Lọc vector
            numbers = [float(num) for num in re.findall(r'\d+', line)]
            vectors.append(numbers)
        vector_array = np.array(vectors)
    return vector_array

if __name__ == "__main__":
    folder_path = "E:\\CNN\\vector_da_noi\\0"
    output_folder = "E:\\CNN\\Anhchong\\0_0"  # Thư mục để lưu ảnh
    os.makedirs(output_folder, exist_ok=True)  # Tạo thư mục nếu chưa tồn tại

    image_shape = (32, 32, 2)  # Set kích thước cho hình ảnh (32x32x2)

    for file_name in os.listdir(folder_path):
        if file_name.endswith('.txt'):
            vector_file = os.path.join(folder_path, file_name)
            vector_array = read_vector_from_txt(vector_file)

            for i, vector in enumerate(vector_array):
                output_image_path = os.path.join(output_folder, f"{file_name}_IMG{i + 1}.jpg")
                vector_to_image(vector, output_image_path, image_shape)
