#
# Author:: Prabhu Das (<prabhu.das@clogeny.com>)
# Copyright:: Copyright (c) 2013 Opscode, Inc.
#

require 'chef/knife/cloud/server/list_command'
require 'chef/knife/ec2_helpers'
require 'chef/knife/cloud/ec2_service_options'
require 'chef/knife/cloud/server/list_options'
require 'pry'
class Chef
  class Knife
    class Cloud
      class Ec2ServerList < ServerListCommand
        include Ec2Helpers
        include Ec2ServiceOptions
        include ServerListOptions

        banner "knife ec2 server list (options)"

        option :az,
          :long => "--availability-zone",
          :boolean => true,
          :default => false,
          :description => "Show availability zones"

        option :tags,
          :short => "-t TAG1,TAG2",
          :long => "--tags TAG1,TAG2",
          :description => "List of tags to output"

        def before_exec_command
          #set columns_with_info map
          @columns_with_info = [
          {:label => 'Instance ID', :key => 'id'},
          {:label => 'Name', :key => 'tags', :value_callback => method(:get_instance_name)},
          {:label => 'Public IP', :key => 'public_ip_address'},
          {:label => 'Private IP', :key => 'private_ip_address'},
          {:label => 'Flavor', :key => 'flavor_id'},
          {:label => 'Image', :key => 'image_id'},
          {:label => 'SSH Key', :key => 'key_name'},
          {:label => 'Security Groups', :key => 'groups'},
          {:label => 'State', :key => 'state'},
          {:label => 'IAM Profile', :key => 'iam_instance_profile'}
          
        ]
          @columns_with_info << {:label => 'AZ', :key => 'availability_zone'} if config[:az]

          if config[:tags]
            config[:tags].split(",").collect do |tag_name|
              @columns_with_info << {:label => 'Tags:'+tag_name, :key => 'tags', :nested_values => tag_name}
            end
          end      
          super
        end

        def get_instance_name(tags)
          return tags['Name'] if tags['Name']
        end  
      end
    end
  end
end
