import requests

header = {"Authorization": "Bearer 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"}
resp = requests.get("https://api.github.com/rate_limit", headers=header)
print(resp)

# from pydriller import Repository
#
# repo = 'https://github.com/ishepard/pydriller'
# for commit in Repository(repo).traverse_commits():
#     print(commit.msg)
#     print(commit.hash)
#     print(commit.insertions)
#     print(commit.deletions)


# # !usr/bin/env python
# # encoding:utf-8
# from __future__ import division
#
# """
# 功能： GitHub项目资源数据自动化下载存储
# """
#
# import os
# from git import Repo
#
#
# def download_github_project(repository_url, local_directory):
#     # 克隆GitHub项目到本地目录
#     Repo.clone_from(repository_url, local_directory)
#
#
# # 项目链接
# github_url = "https://gitclone.com/github.com/jcollie/asterisk"
# repository = github_url.split("/")[-1].strip()
# # 本地目录
# localDir = "projects/"
# saveDir = localDir + repository + "/"
# if not os.path.exists(saveDir):
#     os.makedirs(saveDir)
# # 下载GitHub项目到本地目录
# download_github_project(github_url, saveDir)

