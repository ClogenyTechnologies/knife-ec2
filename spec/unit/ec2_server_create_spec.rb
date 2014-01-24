# Author:: Prabhu Das (<prabhu.das@clogeny.com>)
# Copyright:: Copyright (c) 2013 Opscode, Inc.

require File.expand_path('../../spec_helper', __FILE__)
require 'chef/knife/ec2_server_create'
require 'support/shared_examples_for_servercreatecommand'
require 'support/shared_examples_for_command'

describe Chef::Knife::Cloud::Ec2ServerCreate do
  ami = Object.new
  ami.define_singleton_method(:root_device_type){}
  ami.define_singleton_method(:platform){""}

  create_instance = Chef::Knife::Cloud::Ec2ServerCreate.new
  create_instance.define_singleton_method(:ami){ami}
  create_instance.define_singleton_method(:post_connection_validations){}

  it_behaves_like Chef::Knife::Cloud::Command, Chef::Knife::Cloud::Ec2ServerCreate.new

  ec2_service = Chef::Knife::Cloud::Ec2Service.new
  create_instance.define_singleton_method(:service){ec2_service}
  
  create_instance.config[:winrm_user] = "test_winrm_user"
  create_instance.config[:ssh_user] = "test_ssh_user"

  context "Windows instance" do
    before do
      create_instance.service.define_singleton_method(:is_image_windows?)  do |img, *arg| 
        true
      end
    end
    it_behaves_like Chef::Knife::Cloud::ServerCreateCommand, create_instance
  end
  
  context "Linux instance" do
    before do
      create_instance.service.define_singleton_method(:is_image_windows?)  do |img, *arg| 
        false
      end
    end
    it_behaves_like Chef::Knife::Cloud::ServerCreateCommand, create_instance
  end
    
  describe "#create_service_instance" do
    it "return Ec2Service instance" do
      instance = Chef::Knife::Cloud::Ec2ServerCreate.new
      expect(instance.create_service_instance).to be_an_instance_of(Chef::Knife::Cloud::Ec2Service)
    end
  end

  describe "#validate_params!" do
    before(:each) do
      @instance = Chef::Knife::Cloud::Ec2ServerCreate.new
      @instance.ui.stub(:error)
      Chef::Config[:knife][:bootstrap_protocol] = "ssh"
      Chef::Config[:knife][:identity_file] = "identity_file"
      Chef::Config[:knife][:image_os_type] = "linux"
      Chef::Config[:knife][:ec2_ssh_key_id] = "ec2_ssh_key"
    end

    after(:all) do
      Chef::Config[:knife].delete(:bootstrap_protocol)
      Chef::Config[:knife].delete(:identity_file)
      Chef::Config[:knife].delete(:image_os_type)
      Chef::Config[:knife].delete(:ec2_ssh_key_id)
    end

    it "run sucessfully on all params exist" do
      expect { @instance.validate_params! }.to_not raise_error
    end

    it "raise error if ssh key is missing" do
      Chef::Config[:knife].delete(:ec2_ssh_key_id)
      expect { @instance.validate_params! }.to raise_error(Chef::Knife::Cloud::CloudExceptions::ValidationError,  " You must provide SSH Key..")
    end
  end

  describe "#before_exec_command" do
    before(:each) do
      @instance = Chef::Knife::Cloud::Ec2ServerCreate.new
      @instance.service = double
      @instance.service.should_receive(:create_server_dependencies)
      @instance.service.should_receive(:is_image_windows?)
      @instance.service.stub_chain(:connection, :images, :get, :root_device_type)
      @instance.ui.stub(:error)
      @instance.ui.stub(:warn)
      @instance.config[:chef_node_name] = "chef_node_name"
      Chef::Config[:knife][:image] = "image"
      Chef::Config[:knife][:flavor] = "flavor"
      Chef::Config[:knife][:ec2_security_groups] = "ec2_security_groups"
      Chef::Config[:knife][:security_group_ids] = "test_ec2_security_groups_id"
      Chef::Config[:knife][:availability_zone] = "test_zone"
      Chef::Config[:knife][:server_create_timeout] = "600"
      Chef::Config[:knife][:ec2_ssh_key_id] = "ec2_ssh_key"
      Chef::Config[:knife][:subnet_id] = "test_subnet_id"
      Chef::Config[:knife][:private_ip_address] = "test_private_ip_address"
      Chef::Config[:knife][:dedicated_instance] = "dedicated_instance"
      Chef::Config[:knife][:placement_group] = "test_placement_group"
      Chef::Config[:knife][:iam_instance_profile] = "iam_instance_profile_name"
      @instance.config[:associate_public_ip] = "test_associate_public_ip"
      @instance.stub(:ami).and_return(double)
      @instance.ami.should_receive(:root_device_type)
      @instance.should_receive(:post_connection_validations)
      @instance.stub(:set_image_os_type)
    end

    after(:each) do
      Chef::Config[:knife].delete(:image)
      Chef::Config[:knife].delete(:flavor)
      Chef::Config[:knife].delete(:ec2_ssh_key_id)
      Chef::Config[:knife].delete(:ec2_security_groups)
      Chef::Config[:knife].delete(:security_group_ids)
      Chef::Config[:knife].delete(:availability_zone)
      Chef::Config[:knife].delete(:server_create_timeout)
    end

    it "set create_options" do
      @instance.before_exec_command
      @instance.create_options[:server_def][:tags]["Name"].should == "chef_node_name" 
      @instance.create_options[:server_def][:image_id].should == "image"
      @instance.create_options[:server_def][:flavor_id].should == "flavor"
      @instance.create_options[:server_def][:key_name].should == "ec2_ssh_key"
      @instance.create_options[:server_def][:groups].should == "ec2_security_groups"
      @instance.create_options[:server_def][:security_group_ids].should == "test_ec2_security_groups_id"
      @instance.create_options[:server_def][:availability_zone].should == "test_zone"
      @instance.create_options[:server_create_timeout].should == "600"
      @instance.create_options[:server_def][:placement_group].should == "test_placement_group"
      @instance.create_options[:server_def][:iam_instance_profile_name].should == "iam_instance_profile_name"
    end

    it "set create_options when vpc_mode? is true." do
      @instance.stub(:vpc_mode?).and_return true
      @instance.before_exec_command
      @instance.create_options[:server_def][:subnet_id].should == "test_subnet_id"
      @instance.create_options[:server_def][:private_ip_address].should == "test_private_ip_address"
      @instance.create_options[:server_def][:tenancy].should == "dedicated"
      @instance.create_options[:server_def][:associate_public_ip].should == "test_associate_public_ip"
      @instance.create_options[:server_def][:groups].should == "ec2_security_groups"
    end

    it "sets create_option ebs_optimized to true when provided with some value." do
      @instance.config[:ebs_optimized] = "some_value"
      @instance.before_exec_command
      @instance.create_options[:server_def][:ebs_optimized].should == "true"
    end

    it "sets create_option ebs_optimized to false when not provided." do
      @instance.before_exec_command
      @instance.create_options[:server_def][:ebs_optimized].should == "false"
    end

    it "adds the specified ephemeral device mappings" do
      @instance.config[:ephemeral] = [ "/dev/sdb", "/dev/sdc", "/dev/sdd", "/dev/sde" ]
      @instance.before_exec_command
      @instance.create_options[:server_def][:block_device_mapping].should == [{ "VirtualName" => "ephemeral0", "DeviceName" => "/dev/sdb" },
                                                   { "VirtualName" => "ephemeral1", "DeviceName" => "/dev/sdc" },
                                                   { "VirtualName" => "ephemeral2", "DeviceName" => "/dev/sdd" },
                                                   { "VirtualName" => "ephemeral3", "DeviceName" => "/dev/sde" }]
    end

    it "doesn't set an IAM server role by default" do
      Chef::Config[:knife].delete(:iam_instance_profile)
      @instance.before_exec_command
      @instance.create_options[:server_def][:iam_instance_profile_name].should == nil
    end

    it "sets the IAM server role when one is specified" do
      @instance.config[:iam_instance_profile] = ['iam-role']
      @instance.before_exec_command
      @instance.create_options[:server_def][:iam_instance_profile_name].should == ['iam-role']
    end
    
    it 'Set Tenancy Dedicated when both VPC mode and Flag is True' do
      Chef::Config[:knife][:dedicated_instance] = "dedicated_instance"
      @instance.stub(:vpc_mode?).and_return true
      @instance.before_exec_command
      @instance.create_options[:server_def][:tenancy].should == "dedicated"
    end
    
    it 'Tenancy should be default with no vpc mode is specified' do
      @instance.config[:dedicated_instance] = true
      @instance.stub(:vpc_mode?).and_return false
      @instance.before_exec_command
      @instance.create_options[:server_def][:tenancy].should == nil
    end

    context "when image is windows" do
      before(:each) do
        @instance.service.stub(:is_image_windows?).and_return(true)
      end

      context "bootstrap protocol winrm" do
        before(:each) do
          @instance.config[:bootstrap_protocol] = "winrm"
          @instance.config[:winrm_user] = "testuser_winrm"
          @instance.config[:winrm_password] = "testpassword_winrm"
        end

        it "user data includes user create script for testuser_winrm" do
          @instance.before_exec_command
          @instance.create_options[:server_def][:user_data].should include("<powershell>")
          @instance.create_options[:server_def][:user_data].should include("</powershell>")
          @instance.create_options[:server_def][:user_data].should include("testuser_winrm")
          @instance.create_options[:server_def][:user_data].should include("$newuser.SetPassword(\"testpassword_winrm\")")
        end

        it "user data includes winrm config script" do
          @instance.before_exec_command
          @instance.create_options[:server_def][:user_data].should include("testuser_winrm")
          @instance.create_options[:server_def][:user_data].should include("winrm quickconfig -q")
          @instance.create_options[:server_def][:user_data].should include("winrm e winrm/config/listener")
          @instance.create_options[:server_def][:user_data].should include("$fwrule = New-Object -ComObject HNetCfg.FwRule")
          @instance.create_options[:server_def][:user_data].should include("$fwrule.Name = \"knife-winrm\"")
          @instance.create_options[:server_def][:user_data].should include("$fwpolicy = New-Object -ComObject HNetCfg.FwPolicy2")
          @instance.create_options[:server_def][:user_data].should include("$fwpolicy.Rules.Add($fwrule)")
        end

        context "winrm-transport set to ssl" do
          before(:each) do
            @instance.config[:winrm_transport] = "ssl"
            @instance.config[:certificate_passwd] = "testwinrmcertgen"
            @instance.config[:cert_hostname_pattern] = "*.compute-1.amazonaws.com"
            @instance.config[:pfx_cert] = "C:\Users\cert.pfx"
            File.should_receive(:binread).with("C:\Users\cert.pfx").and_return(" \n")
            Base64.stub(:encode64).and_return("")
          end

          it "user data includes winrm ssl configuration commands" do
            @instance.config[:preserve_winrm_http] = false
            @instance.before_exec_command
            @instance.create_options[:server_def][:user_data].should include("testuser_winrm")
            @instance.create_options[:server_def][:user_data].should include("winrm quickconfig -q")
            @instance.create_options[:server_def][:user_data].should include("winrm e winrm/config/listener")
            @instance.create_options[:server_def][:user_data].should include("winrm delete winrm/config/Listener?Address=*+Transport=HTTP")
            @instance.create_options[:server_def][:user_data].should include("$winrmcmd = \"winrm create winrm/config/listener?Address=*+Transport=HTTPS @{Hostname=`\"*.compute-1.amazonaws.com`\";CertificateThumbprint=`\"$thumbprint`\";Port=`\"5986`\"}\"")
            @instance.create_options[:server_def][:user_data].should include("$fwrule = New-Object -ComObject HNetCfg.FwRule")
            @instance.create_options[:server_def][:user_data].should include("$fwrule.LocalPorts = 5986")
            @instance.create_options[:server_def][:user_data].should include("$fwrule.Description = \"Open winrm ssl port\"")
          end

          it "user data includes winrm ssl configuration with preserve_winrm_http" do
            @instance.config[:preserve_winrm_http] = true
            @instance.before_exec_command
            @instance.create_options[:server_def][:user_data].should include("testuser_winrm")
            @instance.create_options[:server_def][:user_data].should_not include("winrm delete winrm/config/Listener?Address=*+Transport=HTTP")
          end
        end
      end

      context "bootstrap protocol is ssh" do
        before(:each) do
          @instance.config[:bootstrap_protocol] = "ssh"
          @instance.config[:ssh_user] = "testuser_ssh"
          @instance.config[:ssh_password] = "testpassword_ssh"
        end

        it "user data include user create script for testuser_ssh" do
          @instance.before_exec_command
          @instance.create_options[:server_def][:user_data].should include("<powershell>")
          @instance.create_options[:server_def][:user_data].should include("</powershell>")
          @instance.create_options[:server_def][:user_data].should include("testuser_ssh")
          @instance.create_options[:server_def][:user_data].should include("testpassword_ssh")
        end
      end

      context "--user-data cli option specified" do
        before(:each) do
          Chef::Config[:knife][:aws_user_data] = "C:\Users\testuser"
          @instance.config[:bootstrap_protocol] = "winrm"
          @instance.config[:winrm_user] = "testuser_winrm"
          @instance.config[:winrm_password] = "testpassword_winrm"
        end

        it "append user data to create user data when script tag is present" do
          File.stub(:read).and_call_original
          File.stub(:read).with("C:\Users\testuser").and_return("<script> echo \"test user data script\" </script>")
          @instance.before_exec_command
          @instance.create_options[:server_def][:user_data].should include("<script> echo \"test user data script\" </script>")
          @instance.create_options[:server_def][:user_data].should include("Starting knife winrm user-data script...")
          @instance.create_options[:server_def][:user_data].should include("testuser_winrm")
          @instance.create_options[:server_def][:user_data].should include("testpassword_winrm")
          @instance.create_options[:server_def][:user_data].should include("$newuser.SetPassword(\"testpassword_winrm\")")
        end

        it "append user data to create user data when powershell tag is present" do
          File.stub(:read).and_call_original
          File.stub(:read).with("C:\Users\testuser").and_return("<powershell> write-host \"test user data script\" </powershell>")
          @instance.before_exec_command
          @instance.create_options[:server_def][:user_data].should include("testuser_winrm")
          @instance.create_options[:server_def][:user_data].should include("testpassword_winrm")
          @instance.create_options[:server_def][:user_data].should include("write-host \"test user data script\"")
          @instance.create_options[:server_def][:user_data].should include("$newuser.SetPassword(\"testpassword_winrm\")")
          
          # check for only two powershell tag (i.e one opening and one closing)
          @instance.create_options[:server_def][:user_data].scan("powershell>").length.should eq(2)
        end
      end      
    end
   
    context "when image is linux" do
      before(:each) do
        @instance.service.stub(:is_image_windows?).and_return(false)
      end
      it "set user_data when aws_user_data is provided." do
        Chef::Config[:knife][:aws_user_data] = "aws_user_data_file_path"
        File.stub(:read).and_return("aws_user_data_values")
        @instance.before_exec_command
        @instance.create_options[:server_def][:user_data].should == "aws_user_data_values"
      end

      it "throws ui warning when aws_user_data is not readable." do
        Chef::Config[:knife][:aws_user_data] = "aws_user_data_file_path"
        @instance.ui.should_receive(:warn).once
        @instance.before_exec_command
      end
    end
  end


  describe "#after_exec_command" do
    before(:each) do
      @instance = Chef::Knife::Cloud::Ec2ServerCreate.new
      @instance.stub(:msg_pair)
      @instance.stub_chain(:service, :connection, :addresses, :detect).and_return(double)
      @instance.server = double
    end

    after(:all) do
      Chef::Config[:knife].delete(:ec2_floating_ip)
    end
   
    it "prints server summary." do
      @instance.service.stub(:get_server_name)
      @instance.server.stub(:id).and_return("instance_id")
      @instance.server.stub_chain(:groups, :join).and_return("groups")
      @instance.server.stub_chain(:security_group_ids, :join).and_return("security_group_ids")
      @instance.stub_chain(:service, :connection, :tags, :create).with(:key => "Name",
                                                        :value => "instance_id",
                                                        :resource_id => "instance_id")
      @instance.server.stub(:root_device_type).and_return("ebs")
      @instance.server.stub_chain(:block_device_mapping, :first).and_return("block_device_mapping")
      @instance.service.stub(:server_summary)
      @instance.should_receive(:bootstrap)
      @instance.after_exec_command
    end
  end

  describe "#before_bootstrap" do
    before(:each) do
      @instance = Chef::Knife::Cloud::Ec2ServerCreate.new
    end

    it "set bootstrap_ip" do
      @instance.stub(:bootstrap_host).and_return("127.0.0.1")
      @instance.before_bootstrap
      @instance.config[:bootstrap_ip_address].should == "127.0.0.1"
    end

    it "raise error on nil bootstrap_ip" do
      @instance.ui.stub(:error)
      @instance.stub(:bootstrap_host).and_return(nil)
      expect { @instance.before_bootstrap }.to raise_error(Chef::Knife::Cloud::CloudExceptions::BootstrapError, "No IP address available for bootstrapping.")
    end
  end

  describe "#bootstrap_host" do
    before(:each) do
      @instance = Chef::Knife::Cloud::Ec2ServerCreate.new
      @instance.server = double
    end

    it "returns bootstrap_host address on --server-connect-attribute cli option set" do
      @instance.config[:server_connect_attribute] = 'private_ip_address'
      @instance.server.stub(:private_ip_address).and_return("127.0.0.1")
      @instance.before_bootstrap
      @instance.config[:bootstrap_ip_address].should == "127.0.0.1"
    end

    it "returns bootstrap_host address on vpc mode is set" do
      @instance.stub(:vpc_mode?).and_return(true)
      @instance.server.stub(:private_ip_address).and_return("127.0.0.1")
      @instance.before_bootstrap
      @instance.config[:bootstrap_ip_address].should == ("127.0.0.1")
    end
  end

  describe "#validate_ebs" do
    before(:each) do
      @instance = Chef::Knife::Cloud::Ec2ServerCreate.new
    end

    it "validate ebs size" do
      @instance.ui.stub(:error)
      @instance.stub(:ami).and_return(double)
      @instance.config[:ebs_size] = "15"
      @instance.ami.stub(:block_device_mapping).and_return([{"volumeSize" => 8}])
      expect { @instance.validate_ebs }.to_not raise_error
    end

    it "raise error on specified ebs-size is less than ami volume size" do
      @instance.ui.stub(:error)
      @instance.stub(:ami).and_return(double)
      @instance.config[:ebs_size] = "5"
      @instance.ami.stub(:block_device_mapping).and_return([{"volumeSize" => 8}])
      expect { @instance.validate_ebs }.to raise_error(Chef::Knife::Cloud::CloudExceptions::ValidationError, "EBS-size is smaller than snapshot '', expect size >= 8")
    end
  end  
end
