from secrets import *
from others import *
from dependencies import *

def main():
    print("Starting the script...")

# Get Date
    date_today = get_current_date()
    print("Date today: " + date_today)

# Initialization of Variables and Queries
    
    query_array = read_queries_from_csv("github_queries.csv")
    query_author_array = get_query_authors_from_csv("github_queries.csv")
    json_file_path_based_on_date = "github_repositories_"+ date_today +".json"
    json_file_path_archive = "github_repositories_archive.json"
    final_repo_data_list = []
    final_repo_name_list = []
    new_repositories = []
    output_directory = 'json_output'

# Check OpenAI API Connection
    print("Checking connection to OpenAI")
    openai_status = is_api_key_valid()
    if openai_status:
        print("Successfully connected to OpenAI")
    else:
        print("Cannot connect to OpenAI. The Script is exiting....")
        sys.exit(1)

# Load Existing Repositories from Archive CSV   
    existing_repo_names = load_existing_repo_names(json_file_path_archive)
    

    for query in query_array:
        print(f"Querying GitHub for repositories with query: {query}")
        repos = g.search_repositories(query=query, stars='<1000')
        print("Removing Duplicates")
        query_repo_count = 0
        for repo in repos:
            if repo.full_name.split('/')[-1] not in existing_repo_names and query_repo_count < 20 :
                new_repositories.append({
                    "Repository Name": repo.full_name,
                    "Query": query,
                    "Query Author": query_author_array[query_array.index(query)]
                })
            
                #new_repositories.append(repo.full_name)
                existing_repo_names.add(repo.full_name)
                query_repo_count += 1

    print(f"Total Repositories:{len(new_repositories)}")
    for new_repo in new_repositories:
            repo_name = new_repo['Repository Name']
            query = new_repo['Query']
            query_author = new_repo['Query Author']
            if new_repo is None:
                continue
            try:
                print(f"Processing repository: {repo_name}")
                repo_data = populate_repo_data(repo_name, query, query_author)
                final_repo_name_list.append({
                "Repository Name": repo_name,
                "Query": query,
                "Query Author": query_author
                })
                final_repo_data_list.append(repo_data)
                 # Define the JSON file name based on the repository name
                json_file_name = os.path.join(output_directory, f"{repo_name.replace('/', '_')}.json")
                
                # Write the repository data to a JSON file
                with open(json_file_name, 'w') as json_file:
                    json.dump(repo_data, json_file, indent=4)
                
                print(f"Data for repository {repo_name} has been written to {json_file_name}")
            except Exception as e:
                print(f"An error occurred: {e}")
                continue

    print("All repositories have been processed.")

    print(f"Appending repositories to JSON file: {json_file_path_archive} and {json_file_path_based_on_date}")
    #Append existing Repository to github_repositories_archive.json
    try:
        append_data_to_json_archive(json_file_path_archive, final_repo_name_list)
    except Exception as e:
        print(f"An error occured while appending data to JSON file: {e}")
        sys.exit(1)

    '''
     for repo_data in final_repo_data_list:
        try:
            append_data_to_json_with_date(json_file_path_based_on_date, repo_data)
        except Exception as e:
            print(f"An error occured while appending data to JSON file: {e}")
            sys.exit(1)
    '''

    print("The script finished successfully")
    g.close()

if __name__ == "__main__":
    main()