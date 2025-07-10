from secrets import oaikey, vtkey, gitkey, oaiendpoint
from dependencies import *
#VT
vt_api_key = vtkey

#OPENAI
openai.base_url = oaiendpoint
openai.api_key = oaikey
openai.api_type = "openai"

#github
github_token = gitkey
auth = Auth.Token(github_token)
g = Github(auth=auth)

def get_current_datetime_with_milliseconds():
    # Get the current date and time
    now = datetime.now()

    # Format the datetime object to include milliseconds
    formatted_datetime = now.strftime('%Y-%m-%d %H:%M:%S')

    return formatted_datetime

def get_current_date():
    # Get the current date and time
    now = datetime.now()

    # Format the datetime to include only date
    formatted_date = now.strftime('%Y-%m-%d')

    return formatted_date

def read_queries_from_csv(file_path):
    query_array = []

    # Open the CSV file
    with open(file_path, mode='r', newline='', encoding='utf-8') as csvfile:
        csvreader = csv.reader(csvfile)

        # Skip the header row
        header = next(csvreader)

        # Find the index of the "Query" column
        query_index = header.index("Query")

        # Read the remaining rows and append the Query values to the list
        for row in csvreader:
            query_array.append(row[query_index])

    return query_array

def get_query_authors_from_csv(file_path):
    query_author_array = []

    # Open the CSV file
    with open(file_path, mode='r', newline='', encoding='utf-8') as csvfile:
        csvreader = csv.reader(csvfile)

        # Skip the header row
        header = next(csvreader)

        # Find the index of the "Query" column
        query_index = header.index("Author")

        # Read the remaining rows and append the Query values to the list
        for row in csvreader:
            query_author_array.append(row[query_index])

    return query_author_array



def get_response(prompt):
    sample_content = """ RealBlindingEDR
    中文介绍

    Note: Starting from v1.5, only exe will be released and the source code will not be updated (except for bug fixes). If you have any needs or questions, please contact: bXl6LnhjZ0BnbWFpbC5jb20=

    Utilize arbitrary address read/write implementation with signed driver: completely blind or kill or permanently turn off AV/EDR.

    If you want to understand the implementation principle, you can refer to the analysis article: AV/EDR 完全致盲 - 清除6大内核回调实现（Chinese）

    Supports blinding/permanent shutdown: 360 Security Guard, 360 Enterprise Edition, Tianqing V10, Tencent Computer Manager, Tinder/Tinder Enterprise Edition, Kaspersky Endpoint Security, AsiaInfo EDR, Windows Defender, AnTian Zhijia.

    Currently tested on 64-bit Windows 7/10/11 and Windows Server 2008R2/2012R2/2016/2019/2022. If you find a problem in a certain version, you can report it through issue and I will adapt it.

    Introduction
    This project implements the clearing of the following kernel callbacks:

    Delete the callback registered by CmRegisterCallback(Ex)
    Delete the callback registered by MiniFilter driver
    Delete the callbacks registered by ObRegisterCallbacks()
    Delete the callback registered by PsSetCreateProcessNotifyRoutine(Ex)
    Delete the callback registered by PsSetCreateThreadNotifyRoutine(Ex)
    Delete the callback registered by PsSetLoadImageNotifyRoutine(Ex)
    After deleting the kernel callback, the following 3 effects can finally be achieved:

    Blinding AV/EDR

    While keeping the AV/EDR process running normally, it makes it impossible to monitor any process/thread activity, any file landing, registry deletion, high-privilege handle acquisition and many other sensitive behaviors. (Not killing directly is to ensure that EDR maintains communication with the master control and avoid being discovered due to disconnection)

    Permanently turn off or disable AV/EDR

    Since the registry and minifilter kernel notification callbacks are deleted, AV/EDR can be permanently turned off (even if the system is restarted) by modifying the registry or directly deleting the AV/EDR file.

    Kill AV/EDR process

    Since the object handle notification callback has been removed, it is now possible to terminate the AV/EDR process with normal administrator user rights.

    Disclaimer
    This project is not targeted at any AV/EDR manufacturers. The code examples are only for research and learning, and are not allowed to be used maliciously. If there is any malicious use, it has nothing to do with me.

    Usage


    Download the exe file from Releases and do anti-virus processing (you can convert the exe into shellcode and write a shellcode loader to load it)

    This project currently supports 4 types of driver applications (corresponding to the corresponding application numbers):

    echo_driver.sys (support win10+)

    dbutil_2_3.sys (support win7+)

    wnBio.sys (supports Windows Version 6.3+)

    GPU-Z.sys(only supports Windows Version 6.1)

    example:

    Use the echo_driver.sys driver for blinding:

    RealBlindingEDR.exe c:\echo_driver.sys 1

    Use the wnBio.sys driver to permanently remove the anti-virus software (essentially renaming the key files of the anti-virus software):

    RealBlindingEDR.exe c:\wnBio.sys 3 clear 

    Tips: If EDR marks these driver files, you can try to modify the hash value of the driver files without affecting the driver signature.

    Effect
    The following demonstration content is not specific to this AV manufacturer, but is only for educational and research purposes. Most AV/EDR manufacturers are affected.

    DemoVideo

    Delete AV/EDR object handle monitoring and kill AV process



    Delete AV/EDR registry monitoring and delete AV registry to permanently shut down AV



    Delete file landing monitoring and AV/EDR own file protection, delete AV files to permanently close AV



    To be done
    Clear the handles related to the Windows ETW event provider in the kernel.
    Try removing WFP related callbacks.
    ...
    Acknowledgments
    Thanks to the following articles and projects for helping me.

    OBREGISTERCALLBACKS AND COUNTERMEASURES
    Windows Anti-Debug techniques - OpenProcess filtering
    Mimidrv In Depth: Exploring Mimikatz’s Kernel Driver
    Part 1: Fs Minifilter Hooking
    EchoDrv
    Windows Kernel Ps Callbacks Experiments
    Silencing the EDR. How to disable process, threads and image-loading detection callbacks
    Removing-Kernel-Callbacks-Using-Signed-Drivers
    EchOh-No! a Vulnerability and PoC demonstration in a popular Minecraft AntiCheat tool """
    response = openai.chat.completions.create(
        model="gpt-4-turbo",
        messages=[
    {"role": "system", "content": 
    """
    You are an AI assistant tasked with summarizing the README of a given GitHub repository and identifying the appropriate TTP (Tactics, Techniques, and Procedures) usage of the tool. The TTP categories are: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, and Impact.
    Your goal is to provide an accurate summary and accurate classifcation of TTP that will help me process Red Team tools effectively.
    When given the content of a README file or a link of the Github Repository, your response should include:

    1. A concise and informative paragraph summarizing the main purpose, features, and usage of the repository.
    2. A one-line identification of the appropriate TTP category. 

    If the repository contains multiple TTP's, determine which is the best suited. You must not have an output of more than one TTP.
    If the repository does not fall into any TTP classification, output the string "N/A" instead in the "TTP" key.
    Strictly output TTP based on the categories. Do not output any response not in the categories of TTP
    Ensure that your output is accurate and informative, and you must stick to the instructions given to you.

    Validate that the TTP field contains only one of the following categories: Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact. If it does not match any of these categories, output "N/A".

    Strictly, your output should be in a JSON Format like this:          
    {
        "TTP": "Your response here",
        "Usage": "Your response  here"
    }
    """
    },
    {"role":"user", "content": f"Here is the content: {sample_content} This is an example only."},
    {"role": "assistant", "content": """ 
    {
        "TTP": "Defense Evasion",
        "Usage": "RealBlindingEDR is a tool designed to disable or manipulate antivirus and Endpoint Detection and Response (EDR) systems on Windows. It operates by deleting or modifying kernel callbacks that are essential for AV/EDR operations, such as process, thread, and file monitoring. The tool supports multiple versions of Windows and requires specific drivers to function. It allows users to permanently turn off or disable AV/EDR systems by modifying the registry or deleting critical AV/EDR files. Additionally, it can kill AV/EDR processes by removing object handle monitoring. The tool is intended for educational and research purposes, emphasizing its use in understanding AV/EDR system vulnerabilities."
    }
    """},
    {"role":"user", "content": prompt}],temperature=0.1)
    response_text = response.choices[0].message.content
    
    return response_text


def extract_data(response, key):
    # Clean the response
    clean_response = response.replace("```json","").replace("```","")
    parsed_json = (f'''{clean_response}''')
    # Parse the cleaned JSON response
    data = json.loads(parsed_json)
    
    # Return the requested data
    return data.get(key)



def get_total_token(prompt):
    encoding = tiktoken.encoding_for_model("gpt-4o")
    input_tokens=encoding.encode(prompt)
    return len(input_tokens)

def check_assets_for_exe(repo_name):
    try:
        asset_container = []
        repo = g.get_repo(repo_name)
        latest_release = repo.get_latest_release()

        for asset in latest_release.get_assets():
            asset_container.append(asset)

        # Check if asset_container has any data
        if asset_container:
            return True
        else:
            return False
    except Exception as e:
        return False
    

def string_split_add_exe(repo_name):
    part_after_slash = repo_name.split('/')[1]
    append_exe = part_after_slash + ".exe"
    return append_exe


def find_exe_files(repo_name, path=""):
    get_name_repo = repo_name.full_name
    repo_exe_to_check = string_split_add_exe(get_name_repo)
    exe_files = []
    contents = repo_name.get_contents(path)
    for content in contents:
        if content.type == "dir":
            # Recursively search in the subdirectory
            if find_exe_files(repo_name, content.path):
                return True
        elif content.type == "file" and content.path.endswith(".exe"):
            exe_files.append(content.path.lower())

    repo_exe_to_check_lower = repo_exe_to_check.lower()

    # Check if the filename of the repo appended with exe exists in the scraped exe files in the content
    if repo_exe_to_check_lower in exe_files:
        return True

    return False



    
    


def populate_repo_data(repo_name, query, query_author):
    #col_names = ["Date", "Repository Name", "Stars", "Creation Date", "URL", "TTP", "Usage","Query", "Query Author"]
    has_ioc = ""
    init_repo = g.get_repo(repo_name)
    repo_fullname = init_repo.full_name
    # Populate List
    #date_time = get_current_datetime_with_milliseconds()
    #repo_obj = g.get_repo(repo)
    #print(repo_obj)
    #Check for exe in repo dir and assets
    #has_exe_file_repo = find_exe_files(init_repo)
    has_releases_assets = check_assets_for_exe(repo_name)
    if has_releases_assets:
        has_ioc = "Yes"
    else:
        has_ioc = "No"
    decoded_content = get_readme_contents(repo_name)
    #repo_formatted_date = init_repo.created_at.strftime('%Y-%m-%d')
    repo_star = init_repo.stargazers_count
    repo_url = f"https://www.github.com/{repo_fullname}"
    repo_query = query
    repo_query_author = query_author
    #last_commit_date = get_latest_commit_date(repo_fullname)
    exe_name = string_split_add_exe(repo_fullname)
    is_available_in_vt = query_reponame_in_vt(exe_name)

    #prompt_for_ttp = "Your task is to identify the MITRE ATT&CK tactic or technique (TTP) that best matches the content of the given GitHub README content. Here is the content: " + decoded_content + "." +" Your answer should be a concise one-liner, for example: 'Defense Evasion'. If you cannot determine the TTP from the provided link, please respond with 'N/A'. Do not leave the response empty."
    #prompt_for_usage = "Your task is to summarize the README.md of the given GitHub repository. Here is the content: " + decoded_content + "." + " Your output should be a concise and informative paragraph that summarizes the main purpose, features, and usage of the repository."
    '''prompt_ini = f"""Your task is to summarize the README of the given GitHub repository content, and give the appropriate TTP usage of the tool. Here is the content:" {decoded_content} "Your response for the readme should be a concise and informative paragraph that summarizes the main purpose, features, and usage of the repository. Your response for the TTP should be one-line. The TTP are any of this:(Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Command and Control, Exfiltration, Impact. Your output should also be in a JSON format like this 
{
    "TTP":"Your response here",
    "Usage: "Your response here"

}
"""
'''
    prompt_ini = f"Here is the content:{decoded_content}"
    #Calculate Token from Prompt
    #input_ttp_token_total = get_total_token(prompt_for_ttp)
    #input_usage_token_total = get_total_token(prompt_for_usage)
    #print(input_usage_token_total)

    #if input_ttp_token_total and input_usage_token_total > 128000:


        
    #repo_ttp_ai = get_response(prompt_for_ttp)
    #repo_usage_ai = get_response(prompt_for_usage)
    response_prompt = get_response(prompt_ini)
    extracted_ttp = extract_data(response_prompt, "TTP")
    extracted_usage = extract_data(response_prompt,"Usage")
    
    repo_data = {
    "Repository Name": repo_fullname,
    "Stars": repo_star,
    "URL": repo_url,
    "TTP": extracted_ttp,
    "Usage": extracted_usage,
    "Has IOC": has_ioc,
    "Is VT available": is_available_in_vt,
    "Query": repo_query,
    "Query Author": repo_query_author
}

#        repo_data.append({
#            "Date": date_time,
#           "Repository Name": repo_name,
#            "Stars": repo_star,
#            "Creation Date": repo_formatted_date,
#            "URL": repo_url,
#            #"TTP": final_response_ttp_data,
#            #"Usage": final_response_usage_data,
#            "Query": repo_query,
#            "Query Author": repo_query_author
#        })


    return repo_data

def get_readme_contents(repo_name):
    # Regex pattern to match files containing "README" in their filename, case-insensitive
    readme_pattern = re.compile(r'readme', re.IGNORECASE)

    # Initialize GitHub API client
    repo = g.get_repo(repo_name)

    # Get the default branch
    default_branch = repo.default_branch

    try:
        loader = GithubFileLoader(
            repo=repo_name,  # the repo name
            branch=default_branch,  # the defaultzqy1 branch name
            access_token=github_token,
            github_api_url="https://api.github.com",
            file_filter=lambda file_path: readme_pattern.search(file_path) is not None
        )
        readme_content = loader.load()
        if readme_content:
            return readme_content[0].page_content
    except Exception as e:
        raise ValueError(f"Error loading README files: {e}")

    raise ValueError("No README files found in the default branch of the repository.")
            

def load_existing_repos(json_file_path):
    existing_repos = []
    try:
        with open(json_file_path, 'r') as file:
            data = json.load(file)
            existing_repos.extend(data)
    except FileNotFoundError:
        pass  # If the file does not exist, we just skip it
    return existing_repos

def load_existing_repo_names(*json_file_path):
    existing_repo_names = set()
    for json_file_path in json_file_path:
        try:
            with open(json_file_path, 'r') as file:
                data = json.load(file)
                for item in data:
                    existing_repo_names.add(item["Repository Name"].split('/')[-1])
        except FileNotFoundError:
            pass  # If the file does not exist, we just skip it
    return existing_repo_names

def append_data_to_json_with_date(json_file_path, repo_data):
    # Check if the file exists
    if os.path.exists(json_file_path):
        # If it exists, read the existing data
        with open(json_file_path, 'r') as f:
            existing_data = json.load(f)
    else:
        existing_data = []

    # Append new data to existing data
    existing_data.extend(repo_data)

    # Write back to the JSON file
    with open(json_file_path, 'w') as f:
        json.dump(existing_data, f, indent=4)

def append_data_to_json_archive(json_file_path, repo_data):
   # Check if the file exists
    if os.path.exists(json_file_path):
        # If it exists, read the existing data
        with open(json_file_path, 'r') as f:
            existing_data = json.load(f)
    else:
        existing_data = []

    # Append new data to existing data
    existing_data.extend(repo_data)

    # Write back to the JSON file
    with open(json_file_path, 'w') as f:
        json.dump(existing_data, f, indent=4)


def is_api_key_valid():
    prompt = "This is a test"
    try:
        response = openai.chat.completions.create(
        model="gpt-4o",
        messages=[
            {"role": "user", "content": prompt}
        ],
    )
    except Exception as e:
        print(f"An error occured: {e}")
        return False
    else:
        return True
    
def query_reponame_in_vt(repo_fullname):
    query = (f'name:{repo_fullname}')
    url = 'https://www.virustotal.com/api/v3/intelligence/search'
    headers = {
        'x-apikey': vt_api_key
    }
    params = {
        'query': query
    }
    response = requests.get(url, headers=headers, params=params)
 
    if response.status_code == 200:
        results = response.json()
        if results.get('data'):
            return f"https://www.virustotal.com/gui/search/name%253A{repo_fullname}/files"
        else:
            return None
    else:
        return f"Error: {response.status_code}, {response.text}"
    

def save_updated_repos(json_file_path, data):
    with open(json_file_path, 'w') as file:
        json.dump(data, file, indent=4)

def get_query_and_author_by_repo_name(json_data, repo_name):
    for repo in json_data:
        if repo["Repository Name"] == repo_name:
            return repo["Query"], repo["Query Author"]
    return None, None