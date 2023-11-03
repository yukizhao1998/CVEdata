import database as db
for table_name in ["commits", "file_change", "repository", "method_change", "bug_inducing_commits",
                   "bug_inducing_file_change", "bug_inducing_method_change"]:
    if db.table_exists(table_name):
        print("find " + table_name)
        db.drop_table(table_name)
        print(db.table_exists(table_name))