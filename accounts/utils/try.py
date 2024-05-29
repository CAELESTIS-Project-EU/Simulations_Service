import xml_to_yaml

def tryCode():
    path="/home/rcecco/BSCprojects/templates_yaml/AML/w4.xml"
    save_document(xml_to_yaml.execution(path), "/home/rcecco/BSCprojects/templates_yaml/AML/w4.yaml")

def save_document(text, file_path):
    try:
        with open(file_path, 'w') as file:
            file.write(str(text))
    except IOError as e:
        print(f"Error: Unable to save document at {file_path}. {e}")

if __name__ == "__main__":
    tryCode()