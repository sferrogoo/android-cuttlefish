//
// Copyright (C) 2022 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <sys/types.h>
#include <unistd.h>

#include "host/commands/cvd/unittests/selector/creation_analyzer_helper.h"

#include "common/libs/utils/environment.h"
#include "common/libs/utils/users.h"
#include "host/commands/cvd/selector/instance_database_utils.h"
#include "host/commands/cvd/selector/selector_constants.h"
#include "host/commands/cvd/types.h"

namespace cuttlefish {
namespace selector {
namespace {

std::string TestUserHome() {
  static const std::string home = StringFromEnv("HOME", "");
  if (!home.empty()) {
    return home;
  }
  auto result = SystemWideUserHome(getuid());
  return (result.ok() ? *result : "");
}

std::string AutoGeneratedHome(const std::string& subdir) {
  auto parent_result = ParentOfAutogeneratedHomes(getuid(), getgid());
  if (!parent_result.ok()) {
    return "";
  }
  std::string parent(*parent_result);
  return parent + "/" + std::to_string(getuid()) + "/" + subdir;
}

}  // namespace

static auto home_test_inputs = testing::Values(
    InputOutput{
        .cmd_args = "cvd start --daemon",
        .selector_args = "--group_name=cf --instance_name=1",
        .android_host_out = "/home/user/download",
        .home = "/usr/local/home/_fake_user",
        .expected_output =
            Expected{.output = OutputInfo{.home = "/usr/local/home/_fake_user",
                                          .host_artifacts_path =
                                              "/home/user/download"},
                     .is_success = true}},
    InputOutput{.cmd_args = "cvd start --daemon",
                /* no selector_args */
                .android_host_out = "/home/user/download",
                .home = TestUserHome(),
                .expected_output =
                    Expected{.output = OutputInfo{.home = TestUserHome(),
                                                  .host_artifacts_path =
                                                      "/home/user/download"},
                             .is_success = true}},
    InputOutput{
        .cmd_args = "cvd start --daemon",
        /* no selector_args */
        .android_host_out = "/home/user/download",
        /* undefined HOME */
        .expected_output = Expected{
            .output = OutputInfo{.home = TestUserHome(),
                                 .host_artifacts_path = "/home/user/download"},
            .is_success = true}});

TEST_P(HomeTest, HomeTest) {
  if (TestUserHome().empty()) {
    /*
     * If $HOME is the same as the real home directory (i.e. HOME is not
     * overridden), cvd uses an automatically generated path in place of
     * HOME when the operation is "start".
     *
     * Otherwise, for backward compatibility, cvd respects the overridden
     * HOME.
     *
     * In testing that feature, if we cannot get the real home directory,
     * the testing is not possible.
     */
    GTEST_SKIP() << "$HOME should be available for this set of tests.";
  }
  auto param = CreationAnalyzer::CreationAnalyzerParam{
      .cmd_args = cmd_args_, .envs = envs_, .selector_args = selector_args_};

  auto result = CreationAnalyzer::Analyze(
      sub_cmd_, param, credential_, instance_db_, instance_lock_file_manager_);

  ASSERT_EQ(result.ok(), expected_success_) << result.error().Trace();
  if (!expected_success_) {
    return;
  }
  ASSERT_EQ(result->home, expected_output_.home);
}

INSTANTIATE_TEST_SUITE_P(CvdCreationInfo, HomeTest, home_test_inputs);

static auto host_out_test_inputs = testing::Values(
    InputOutput{.cmd_args = "cvd start --daemon",
                .selector_args = "--group_name=cf --instance_name=1",
                .android_host_out = "/home/user/download",
                .home = "/home/fake_user",
                .expected_output =
                    Expected{.output = OutputInfo{.home = "/home/fake_user",
                                                  .host_artifacts_path =
                                                      "/home/user/download"},
                             .is_success = true}},
    InputOutput{.cmd_args = "cvd start --daemon",
                .selector_args = "--group_name=cf --instance_name=1",
                /* missing ANDROID_HOST_OUT */
                .home = "/home/fake_user",
                .expected_output =
                    Expected{.output = OutputInfo{.home = "/home/fake_user"},
                             .is_success = false}});

TEST_P(HostArtifactsTest, HostArtifactsTest) {
  auto param = CreationAnalyzer::CreationAnalyzerParam{
      .cmd_args = cmd_args_, .envs = envs_, .selector_args = selector_args_};

  auto result = CreationAnalyzer::Analyze(
      sub_cmd_, param, credential_, instance_db_, instance_lock_file_manager_);

  ASSERT_EQ(result.ok(), expected_success_) << result.error().Trace();
  if (!expected_success_) {
    return;
  }
  ASSERT_EQ(result->host_artifacts_path, expected_output_.host_artifacts_path);
}

INSTANTIATE_TEST_SUITE_P(CvdCreationInfo, HostArtifactsTest,
                         host_out_test_inputs);

static auto invalid_sub_cmd_test_inputs =
    testing::Values(InputOutput{.cmd_args = "cvd stop --daemon",
                                .android_host_out = "/home/user/download",
                                .home = "/home/fake_user"},
                    InputOutput{.cmd_args = "cvd",
                                .android_host_out = "/home/user/download",
                                .home = "/home/fake_user"},
                    InputOutput{.cmd_args = "cvd help --daemon",
                                .android_host_out = "/home/user/download",
                                .home = "/home/fake_user"});

TEST_P(InvalidSubCmdTest, InvalidSubCmdTest) {
  auto param = CreationAnalyzer::CreationAnalyzerParam{
      .cmd_args = cmd_args_, .envs = envs_, .selector_args = selector_args_};

  auto result = CreationAnalyzer::Analyze(
      sub_cmd_, param, credential_, instance_db_, instance_lock_file_manager_);

  ASSERT_FALSE(result.ok())
      << "Analyze() had to fail with the subcmd in " << GetParam().cmd_args;
}

INSTANTIATE_TEST_SUITE_P(CvdCreationInfo, InvalidSubCmdTest,
                         invalid_sub_cmd_test_inputs);

static auto& valid_sub_cmd_test_inputs = home_test_inputs;

TEST_P(ValidSubCmdTest, ValidSubCmdTest) {
  auto param = CreationAnalyzer::CreationAnalyzerParam{
      .cmd_args = cmd_args_, .envs = envs_, .selector_args = selector_args_};

  auto result = CreationAnalyzer::Analyze(
      sub_cmd_, param, credential_, instance_db_, instance_lock_file_manager_);

  ASSERT_TRUE(result.ok()) << result.error().Trace();
}

INSTANTIATE_TEST_SUITE_P(CvdCreationInfo, ValidSubCmdTest,
                         valid_sub_cmd_test_inputs);

/*
 * Tries to run Cuttlefish with default group two times, so the second
 * run should fail as the default group_name is registed in the Instance-
 * Database.
 */
TEST(AutoHomeTest, DefaultFailAtSecondTrialTest) {
  auto android_host_out = StringFromEnv("ANDROID_HOST_OUT", ".");
  if (android_host_out.empty()) {
    GTEST_SKIP() << "This test requires ANDROID_HOST_OUT to be set";
  }
  auto credential = ucred{.pid = getpid(), .uid = getuid(), .gid = getgid()};
  InstanceLockFileManager lock_manager;
  InstanceDatabase instance_db;
  cvd_common::Envs envs = {{"ANDROID_HOST_OUT", android_host_out}};
  cvd_common::Args empty_args;
  std::vector<cvd_common::Args> cmd_args_list{
      cvd_common::Args{"--daemon", "--instance_nums=7"},
      cvd_common::Args{"--daemon", "--instance_nums=3"}};
  auto param0 = CreationAnalyzer::CreationAnalyzerParam{
      .cmd_args = cmd_args_list[0], .envs = envs, .selector_args = empty_args};
  auto param1 = CreationAnalyzer::CreationAnalyzerParam{
      .cmd_args = cmd_args_list[1], .envs = envs, .selector_args = empty_args};

  auto result_1st_exec = CreationAnalyzer::Analyze("start", param0, credential,
                                                   instance_db, lock_manager);
  auto result_db_addition =
      instance_db.AddInstanceGroup("cvd", TestUserHome(), android_host_out);
  if (!result_db_addition.ok()) {
    GTEST_SKIP() << "This test requires mock group addition to work.";
  }
  auto result_2nd_exec = CreationAnalyzer::Analyze("start", param1, credential,
                                                   instance_db, lock_manager);

  ASSERT_TRUE(result_1st_exec.ok()) << result_1st_exec.error().Trace();
  ASSERT_EQ(result_1st_exec->home, TestUserHome());
  ASSERT_FALSE(result_2nd_exec.ok())
      << "Meant to be fail but returned home : " << result_2nd_exec->home;
}

TEST(AutoHomeTest, DefaultFollowedByNonDefaultTest) {
  auto android_host_out = StringFromEnv("ANDROID_HOST_OUT", ".");
  if (android_host_out.empty()) {
    GTEST_SKIP() << "This test requires ANDROID_HOST_OUT to be set";
  }
  if (AutoGeneratedHome("goog").empty()) {
    GTEST_SKIP() << "This test requires read-writable temp directory";
  }
  auto credential = ucred{.pid = getpid(), .uid = getuid(), .gid = getgid()};
  InstanceLockFileManager lock_manager;
  InstanceDatabase instance_db;
  cvd_common::Envs envs = {{"ANDROID_HOST_OUT", android_host_out}};
  // needs this as the CreationAnalyzerParam takes references, not copies.
  // i.e. .cmd_args = cvd_common::Args{} won't work.
  cvd_common::Args empty_args;
  cvd_common::Args cmd_arg_for_default{"--daemon", "--instance_nums=7"};
  cvd_common::Args cmd_args_1st_non_default{"--daemon", "--instance_nums=3"};
  cvd_common::Args cmd_args_2nd_non_default{"--daemon", "--instance_nums=5"};
  cvd_common::Args selector_device_name_args{"--group_name=goog",
                                             "--instance_name=tv"};
  auto param_default =
      CreationAnalyzer::CreationAnalyzerParam{.cmd_args = cmd_arg_for_default,
                                              .envs = envs,
                                              .selector_args = empty_args};
  auto param_1st_non_default = CreationAnalyzer::CreationAnalyzerParam{
      .cmd_args = cmd_args_1st_non_default,
      .envs = envs,
      .selector_args = selector_device_name_args};
  // To make second non-default run non-default.
  cvd_common::Envs envs_with_home{envs};
  envs_with_home["HOME"] = "/home/mocktester";
  auto param_2nd_non_default = CreationAnalyzer::CreationAnalyzerParam{
      .cmd_args = cmd_args_2nd_non_default,
      .selector_args = empty_args,
      .envs = envs_with_home};

  auto result_default = CreationAnalyzer::Analyze(
      "start", param_default, credential, instance_db, lock_manager);
  auto result_db_addition =
      instance_db.AddInstanceGroup("cvd", TestUserHome(), android_host_out);
  if (!result_db_addition.ok()) {
    GTEST_SKIP() << "This test requires mock group addition to work.";
  }
  auto result_1st_non_default = CreationAnalyzer::Analyze(
      "start", param_1st_non_default, credential, instance_db, lock_manager);
  auto result_2nd_non_default = CreationAnalyzer::Analyze(
      "start", param_2nd_non_default, credential, instance_db, lock_manager);

  ASSERT_TRUE(result_default.ok()) << result_default.error().Trace();
  ASSERT_EQ(result_default->home, TestUserHome());
  ASSERT_TRUE(result_1st_non_default.ok())
      << result_1st_non_default.error().Trace();
  ASSERT_EQ(result_1st_non_default->home, AutoGeneratedHome("goog"));
  ASSERT_TRUE(result_2nd_non_default.ok())
      << result_2nd_non_default.error().Trace();
}

}  // namespace selector
}  // namespace cuttlefish
