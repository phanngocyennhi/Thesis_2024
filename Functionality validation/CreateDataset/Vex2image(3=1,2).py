import cv2
import numpy as np
import re
import os
import glob

def vector_to_image(vector, output_image_path, image_shape):

    # Chia vector thành 2 ma trận 32x32
    image_channels = np.split(vector, 2)

    # Chuyển đổi mỗi ma trận thành ảnh 32x32, 
    image = np.stack([channel.reshape((32, 32)) for channel in image_channels], axis=-1)
    #image = np.concatenate((image, image[:, :, 0:1]), axis=2)  #với kênh thứ 3 là bản copy của kênh 1
    image = np.concatenate((image, image[:, :, 1:2]), axis=2)  #với kênh thứ 3 là bản copy của kênh 2
    
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

#hàm main sau khi có hạn chế số lượng gen ảnh
if __name__ == "__main__":
    folder_path = "E:\\Binkit\\Vector ghép\\cppi\\"
    output_folder = "E:\\Binkit\\Ảnh(3=2)\\1\\"  # Thư mục để lưu ảnh
    os.makedirs(output_folder, exist_ok=True)  # Tạo thư mục nếu chưa tồn tại

    image_shape = (32, 32, 2)  # Set kích thước cho hình ảnh (2x1024)

    image_count = 0  # Biến đếm số lượng ảnh đã tạo

    for file_name in os.listdir(folder_path):
        if file_name.endswith('.txt'):
            vector_file = os.path.join(folder_path, file_name)
            vector_array = read_vector_from_txt(vector_file)

            for i, vector in enumerate(vector_array):
                if image_count >= 1:
                    break  # Dừng lại nếu đã tạo đủ 5000 ảnh
                output_image_path = os.path.join(output_folder, f"{file_name}_IMG{i + 1}.png")
                vector_to_image(vector, output_image_path, image_shape)
                image_count += 1

