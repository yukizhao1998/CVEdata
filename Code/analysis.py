import sqlite3
import sys
from sqlite3 import Error
import configuration as cf
import json
import pandas as pd
from collections import defaultdict

conn = None

def create_connection(db_file):
    """
    create a connection to sqlite3 database
    """
    try:
        return sqlite3.connect(db_file, timeout=10)  # connection via sqlite3
    except Error as e:
        cf.logger.critical(e)
        sys.exit(1)

def fetch_query(query):
    """
    checks whether table exists or not
    :returns boolean yes/no
    """
    cursor = conn.cursor()
    cursor.execute(query)
    result = cursor.fetchall()
    return result if not None else False

def execute(query):
    cursor = conn.cursor()
    result = cursor.execute(query)
    return result if not None else False

def analyze_quantity():
    repo_summary = json.load(open("./database_file/repo_summary.json", "r"))
    success_repos = repo_summary["success"].keys()
    fail_repos = []
    for repo in repo_summary["fail"].keys():
        if repo_summary["fail"][repo] == "Problem occurred while retrieving the project":
            continue
        else:
            fail_repos.append(repo)
    print("retrieved repos:", len(success_repos), len(fail_repos))

    sql = "select count(distinct x.cve_id) from fixes x, bug_inducing_commits c where x.hash = c.fix_hash"
    print("cve:", fetch_query(sql))

    sql = "select count(distinct x.hash) from fixes x, bug_inducing_commits c where x.hash = c.fix_hash"
    print("fix commits:", fetch_query(sql))

    # sql = "SELECT name FROM sqlite_master WHERE type='table';"
    # print(fetch_query(sql))

    sql = "select count(distinct cc.cwe_id) from cwe_classification cc where cc.cve_id in (select distinct x.cve_id from fixes x, bug_inducing_commits c where x.hash = c.fix_hash)"
    print("cwes:", fetch_query(sql))

    sql = "select count(distinct hash) from bug_inducing_commits"
    print("vics:", fetch_query(sql))

def show_example(url):
    cves_sql = "select hash from fixes where repo_url=" + url
    print(pd.read_sql_query("select * from fixes where repo_url=" + url, conn))
    print(dict(pd.read_sql_query(cves_sql, conn)))
    fix_commits_sql = f"select * from bug_inducing_commits where fix_hash in ({cves_sql})"
    df = pd.read_sql_query(fix_commits_sql, conn)
    print(dict(df))
    print(dict(pd.read_sql_query("select * from bug_inducing_file_change where hash=" + "\'2f7a4168fd314c0fb4be41111431e95f8879cfd8\'", conn)))
    print(dict(pd.read_sql_query(
        "select * from bug_inducing_method_change where file_change_id=" + "\'125233617006873\'", conn)))


def analyze_cwe():
    sql = "select cc.cwe_id, count(*) as count from cwe_classification cc where cc.cve_id in (select distinct x.cve_id from fixes x, bug_inducing_commits c where x.hash = c.fix_hash) group by cc.cwe_id order by count desc"
    df = pd.read_sql_query(sql, conn)
    total = 0
    for idx, row in df.iterrows():
        if row["cwe_id"] == "NVD-CWE-noinfo" or row["cwe_id"] == "NVD-CWE-Other":
            continue
        total += row["count"]
    sum = 0
    for idx, row in df.iterrows():
        if row["cwe_id"] == "NVD-CWE-noinfo" or row["cwe_id"] == "NVD-CWE-Other":
            continue
        sum += row["count"]
        print(idx, row["cwe_id"], row["count"], "accumulate:", sum / total)


def analyze_line_prop():
    df = pd.read_sql_query("select vfc.hash as vfc_hash, vic.hash as vic_hash from commits vfc, bug_inducing_commits vic where vfc.hash=vic.fix_hash", conn)
    vfc_vic_dict = defaultdict(list)
    for idx, row in df.iterrows():
        vfc_vic_dict[row["vfc_hash"]].append(row["vic_hash"])
    cnt = 0
    res = dict()
    for gran in ("c", "f", "m"):
        res[gran] = {}
        for line in ("t", "r", "p"):
            res[gran][line] = []
    for key in vfc_vic_dict:
        cnt += 1
        print(cnt, len(vfc_vic_dict.keys()), cnt / len(vfc_vic_dict.keys()))
        vfc_hash = key
        delete_dict = defaultdict(dict)
        df1 = pd.read_sql_query(f"select * from file_change where hash='{vfc_hash}'", conn)
        # files
        for idx1, row1 in df1.iterrows():
            filename = row1["filename"]
            delete_rows = eval(row1["diff_parsed"])["deleted"]
            df2 = pd.read_sql_query(
                f"select * from method_change where file_change_id='{row1['file_change_id']}' and before_change='True'", conn)
            for idx2, row2 in df2.iterrows():
                method_name = row2["name"]
                start_line = row2["start_line"]
                end_line = row2["end_line"]
                for delete_row in delete_rows:
                    if int(end_line) >= int(delete_row[0]) >= int(start_line):
                        if method_name in delete_dict[filename].keys():
                            delete_dict[filename][method_name].append(delete_row[1])
                        else:
                            delete_dict[filename][method_name] = [delete_row[1]]
        # commits
        for vic_hash in vfc_vic_dict[vfc_hash]:
            add_dict = defaultdict(dict)
            df1 = pd.read_sql_query(f"select * from bug_inducing_file_change where hash='{vic_hash}'", conn)
            c_t = 0
            c_r = 0
            # files
            for idx1, row1 in df1.iterrows():
                f_t = 0
                f_r = 0
                filename = row1["filename"]
                add_rows = eval(row1["diff_parsed"])["added"]
                df2 = pd.read_sql_query(f"select * from bug_inducing_method_change where file_change_id='{row1['file_change_id']}' and before_change='False'", conn)
                # methods
                for idx2, row2 in df2.iterrows():
                    m_t = 0
                    m_r = 0
                    method_name = row2["name"]
                    start_line = row2["start_line"]
                    end_line = row2["end_line"]
                    for add_row in add_rows:
                        if int(end_line) >= int(add_row[0]) >= int(start_line):
                            if method_name in add_dict[filename].keys():
                                add_dict[filename][method_name].append(add_row[1])
                            else:
                                add_dict[filename][method_name] = [add_row[1]]
                            m_t += 1
                            if filename in delete_dict.keys() and method_name in delete_dict[filename].keys() and add_row[1] in delete_dict[filename][method_name]:
                                m_r += 1
                    if m_r != 0:
                        res["m"]["t"].append(m_t)
                        res["m"]["r"].append(m_r)
                    f_t += m_t
                    f_r += m_r
                if f_r != 0:
                    res["f"]["t"].append(f_t)
                    res["f"]["r"].append(f_r)
                c_t += f_t
                c_r += f_r
            if c_r != 0:
                res["c"]["t"].append(c_t)
                res["c"]["r"].append(c_r)
    for gran in ("c", "f", "m"):
        for line in ("t", "r"):
            res[gran][line] = sum(res[gran][line]) / len(res[gran][line])
        res[gran]["p"] = res[gran]["r"] / res[gran]["t"]
    print(res)



if __name__ == "__main__":
    conn = create_connection("./database_file/CVEfixes_sample.db")
    analyze_quantity()
    # show_example("\'https://github.com/YunoHost-Apps/transmission_ynh\'")
    # analyze_cwe()
    #
    # 114598470636438, 87637561592026
    # df = pd.read_sql_query("select * from method_change where file_change_id='114598470636438' and before_change='True'", conn)
    # print(df)
    # for idx, row in df.iterrows():
    #     print(row)
    # df = pd.read_sql_query(
    #     "select * from bug_inducing_file_change where hash=" + "\'2f7a4168fd314c0fb4be41111431e95f8879cfd8\'", conn)
    # for idx, row in df.iterrows():
    #     if idx == 2:
    #         print(row)
    #     print(row["diff_parsed"])
    analyze_line_prop()
    # df = pd.read_sql_query(
    #     "select * from bug_inducing_method_change limit 1", conn)
    # for idx, row in df.iterrows():
    #     print(row)