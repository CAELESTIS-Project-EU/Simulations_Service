import xml.etree.ElementTree as ET
import logging

log = logging.getLogger(__name__)

def workflow_type_parser(root):
    workflow_definition_element = root
    if workflow_definition_element is not None:
        value_element = workflow_definition_element.find('.//{http://www.dke.de/CAEX}Value')
        if value_element is not None:
            workflow_definition_value = value_element.text
            return workflow_definition_value
    raise Exception("Workflow_definition element not found")

def inputs_parser(root):
    namespace = {"caex": "http://www.dke.de/CAEX"}
    inputs_data = {}

    if root is not None:
        inputs_element = root.find('.//caex:InternalElement[@Name="Inputs"]',namespaces=namespace)
        if inputs_element is not None:
            for internal_element in inputs_element.findall('.//caex:InternalElement', namespaces=namespace):
                internal_element_name = internal_element.get('Name')
                attribute_source = internal_element.find('.//caex:Attribute[@Name="server"]/caex:Value', namespaces=namespace)
                attribute_destination = internal_element.find('.//caex:Attribute[@Name="path"]/caex:Value', namespaces=namespace)

                if attribute_source is not None and attribute_destination is not None:
                    source_value = attribute_source.text if attribute_source.text is not None else ''
                    destination_value = attribute_destination.text if attribute_destination.text is not None else ''

                    inputs_data[internal_element_name] = [
                        {'server': source_value},
                        {'path': destination_value}
                    ]

    return inputs_data



def outputs_parser(root):
    namespace = {"caex": "http://www.dke.de/CAEX"}
    outputs_data = {}
    if root is not None:
        outputs_element = root.find('.//caex:InternalElement[@Name="Outputs"]', namespaces=namespace)
        if outputs_element is not None:
            for internal_element in outputs_element.findall('.//caex:InternalElement', namespaces=namespace):
                internal_element_name = internal_element.get('Name')
                attribute_source = internal_element.find('.//caex:Attribute[@Name="path"]/caex:Value', namespaces=namespace)
                attribute_destination = internal_element.find('.//caex:Attribute[@Name="server"]/caex:Value', namespaces=namespace)

                if attribute_source is not None and attribute_destination is not None:
                    source_value = attribute_source.text if attribute_source.text is not None else ''
                    destination_value = attribute_destination.text if attribute_destination.text is not None else ''

                    # Use the dynamic value as the key for outputs_data
                    outputs_data[internal_element_name] = [
                        {'path': source_value},
                        {'server': destination_value},
                        {'overwrite': True}  # Assuming you always want to set overwrite to True
                    ]

        return outputs_data


def phases_parser(root):
    namespace = {"caex": "http://www.dke.de/CAEX"}
    phases_data = {}

    if root is not None:
        # Locate the Phases InternalElement
        phases_element = root.find('.//caex:InternalElement[@Name="Phases"]', namespaces=namespace)
        if phases_element is not None:
            # Locate Phase elements
            phase_elements = phases_element.findall('.//caex:InternalElement[@Name="Phase"]', namespaces=namespace)
            for phase_element in phase_elements:
                phase_info = {}

                # Extract phase name
                phase_name_element = phase_element.find('.//caex:Attribute[@Name="Name"]/caex:Value',
                                                        namespaces=namespace)
                if phase_name_element is not None:
                    phase_name = phase_name_element.text
                else:
                    continue  # Skip if no phase name is found

                # Extract sequence information
                sequence_value_element = phase_element.find('.//caex:Attribute[@Name="Sequence"]/caex:Value',
                                                            namespaces=namespace)
                if sequence_value_element is not None:
                    sequence_value = sequence_value_element.text
                    sequence_list = sequence_value.split(">>")
                else:
                    sequence_list = []

                software_list = []

                # Iterate over software elements within the phase based on sequence
                for seq in sequence_list:
                    software_element = phase_element.find('.//caex:InternalElement[@Name="' + seq + '"]',
                                                          namespaces=namespace)
                    if software_element is not None:
                        software_info = {}

                        # Extract software type
                        type_element = software_element.find('.//caex:Attribute[@Name="Type"]/caex:Value',
                                                             namespaces=namespace)
                        if type_element is not None:
                            software_info['Type'] = type_element.text

                        # Extract parameters
                        parameters_data = {}
                        parameters_element = software_element.find('.//caex:InternalElement[@Name="Parameters"]',
                                                                   namespaces=namespace)
                        if parameters_element is not None:
                            for attribute_element in parameters_element.findall('.//caex:Attribute',
                                                                                namespaces=namespace):
                                attribute_name = attribute_element.get('Name')
                                value_element = attribute_element.find('.//caex:Value', namespaces=namespace)
                                if value_element is not None:
                                    attribute_value = value_element.text
                                    parameters_data[attribute_name] = attribute_value

                        software_info['parameters'] = parameters_data
                        software_list.append(software_info)

                phases_data[phase_name] = software_list

    return phases_data


def convert_string(string):
    result = string
    start_index = 0
    while True:
        # Find the next occurrence of '{'
        start_index = result.find('{', start_index)
        if start_index == -1:
            break  # No more occurrences found
        # Find the end of the variable name
        end_index = result.find('}', start_index)
        if end_index == -1:
            break  # Malformed string, exit loop
        # Replace the variable name and surrounding curly braces with '$' and the variable name
        result = result[:start_index] + '$' + result[start_index+1:end_index] + result[end_index+1:]
        # Move the start index to the next character after the replaced part
        start_index = end_index + 1
    return result


def parameters_parser(root):
    namespace = {"caex": "http://www.dke.de/CAEX"}
    parameters_data = {}
    if root is not None:
        params_element = root.find('.//caex:InternalElement[@Name="Parameters"]', namespaces=namespace)
        if params_element is not None:
            for internal_element in params_element.findall('.//caex:InternalElement', namespaces=namespace):
                internal_element_name = internal_element.get('Name')
                attribute_param = internal_element.find('.//caex:Attribute[@Name="Param"]/caex:Value',
                                                         namespaces=namespace)

                if attribute_param is not None :
                    param_value = attribute_param.text if attribute_param.text is not None else ''
                    parameters_data[internal_element_name]=param_value
    return parameters_data

def workflow_parser(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    root = root.find('.//{http://www.dke.de/CAEX}InternalElement[@Name="Workflow_definition"]')

    workflow_data = {'workflow_type': None, 'phases': [], 'outputs': {}, 'inputs': {}, 'parameters': {}}
    workflow_data['workflow_type'] = workflow_type_parser(root)
    workflow_data['inputs'] = inputs_parser(root)
    workflow_data['outputs'] = outputs_parser(root)
    workflow_data['phases'] = phases_parser(root)
    workflow_data['parameters'] = parameters_parser(root)
    return workflow_data


def execution(path):
    try:
        result = workflow_parser(path)
        return result
    except Exception as e:
        print(f"Error: {e}")


