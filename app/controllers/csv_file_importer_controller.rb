require 'csv'
require 'tempfile'
require 'iconv'

class MultipleIssuesForUniqueValue < Exception
end

class NoIssueForUniqueValue < Exception
end

class Journal < ActiveRecord::Base
	def empty?(*args)
		(details.empty? && notes.blank?)
	end
end

class CsvFileImporterController < ApplicationController
	unloadable

	before_filter :find_project, :get_settings

	ISSUE_ATTRS = [:id, :subject, :assigned_to, :fixed_version,
		:author, :description, :category, :priority, :tracker, :status,
		:start_date, :due_date, :done_ratio, :estimated_hours,
		:parent_issue, :watchers, :created_on ]

	TIME_ENTRY_ATTRS = [:issue_id, :comments, :activity_id, :spent_on, :hours, :user_id]

	def index
	end

	def match
	    # Delete existing iip to ensure there can't be two iips for a user
	    CsvFileImportInProgress.delete_all(["user_id = ?",User.current.id])
	    # save import-in-progress data
	    iip = CsvFileImportInProgress.find_or_create_by(user_id: User.current.id) 
	    iip.import_type = params[:import_type]
	    iip.quote_char = params[:wrapper]
	    iip.col_sep = params[:splitter]
	    iip.encoding = params[:encoding]

	    #iip.csv_data = params[:file].read
	    iip.created = Time.new
	    if params[:file]
	    	iip.csv_data = params[:file].read
	    else
	    	flash[:warning] = l(:text_file_not_specified)
	    	redirect_to :action => 'index', :project_id => @project.id
	    	return
	    end
	    iip.save

	    # Put the timestamp in the params to detect
	    # users with two imports in progress
	    @import_timestamp = iip.created.strftime("%Y-%m-%d %H:%M:%S")
	    @original_filename = params[:file].original_filename

	    # display sample
	    sample_count = 5
	    i = 0
	    @samples = []

		# Detects real encoding and converts as necessary
		latin = latin_encoding(iip.encoding, iip.csv_data)
		if latin[:latin]
			iip.csv_data = latin[:data]
			iip.encoding = latin[:encoding]
		end

		begin
			CSV.new(iip.csv_data, {:headers=>true,
				:converters => :all,
				:encoding=>iip.encoding,
				:quote_char=>iip.quote_char,
				:col_sep=>iip.col_sep}).each do |row|

				@samples[i] = row

				i += 1
				if i >= sample_count
					break
				end
	      	end # do
		rescue => e
			msg = "[CsvFileImporterController.match] " + e.message + "\n" + e.backtrace.join("\n")
			logger.debug msg
			render :text => "CSV file read error: encoding error or " + e.message
			return
		end

		if @samples.size > 0
			@headers = @samples[0].headers

			(0..@headers.size-1).each do |num|
				unless @headers[num]
					@headers[num] = '------'
					flash[:warning] = "Column name empty error"
				end
			    # header encoding
			    @headers[num].to_s.force_encoding("utf-8")
			end
		end

		logger.info "[CsvFileImporterController.match] Import type : #{iip.import_type}"
		case iip.import_type
			when 'issue'
				attributes = ISSUE_ATTRS
				render_template = 'issue'
				
			when 'time_entry'
				attributes = TIME_ENTRY_ATTRS
				render_template = 'time_entry'
		end

	    # fields
	    @attrs = Array.new
	    attributes.each do |attr|
	    	@attrs.push([l_or_humanize(attr, :prefix=>"field_"), attr])
	    end

	    @project.all_issue_custom_fields.each do |cfield|
	    	@attrs.push([cfield.name, cfield.name])
	    end

	    IssueRelation::TYPES.each_pair do |rtype, rinfo|
	    	@attrs.push([l_or_humanize(rinfo[:name]),rtype])
	    end

	    @attrs.sort!

	    logger.info "[CsvFileImporterController.match] Render : match_#{render_template}"
	    render(:template => "csv_file_importer/match_" + render_template)
	end

	# Returns the issue object associated with the given value of the given attribute.
	# Raises NoIssueForUniqueValue if not found or MultipleIssuesForUniqueValue
	def issue_for_unique_attr(unique_attr, attr_value, row_data)
		if @issue_by_unique_attr.has_key?(attr_value)
			return @issue_by_unique_attr[attr_value]
		end

		if !(attr_value.blank?) && !(attr_value.to_s =~ /^\d+$/)
			attr_value = attr_value[/#\d+:/].blank? ? attr_value : attr_value[/#\d+:/][/\d+/]
		end

		if unique_attr == "id"
			issues = [Issue.find_by_id(attr_value)]
		else
			query = IssueQuery.new(:name => "_csv_file_importer", :project => @project)
			query.add_filter("status_id", "*", [1])
			query.add_filter(unique_attr, "=", [attr_value])

			begin
				issues = Issue.find :all, :conditions => query.statement, :limit => 2, :include => [ :assigned_to, :status, :tracker, :project, :priority, :category, :fixed_version ]
			rescue NoMethodError
				query = IssueQuery.new(:name => "_csv_file_importer", :project => @project)
				query.add_filter("status_id", "*", [1])
				query.add_filter(unique_attr, "=", [attr_value.to_s])
				issues = Issue.find :all, :conditions => query.statement, :limit => 2, :include => [ :assigned_to, :status, :tracker, :project, :priority, :category, :fixed_version ]
			end
		end
		if issues.size > 1
			@failed_count += 1
			@failed_issues[@failed_count] = row_data
			flash_message(:warning, "Unique field #{unique_attr}#{unique_attr == @unique_attr ? '': '('+@unique_attr+')'} with value '#{attr_value}' has duplicate record")
			raise MultipleIssuesForUniqueValue, "Unique field #{unique_attr} with value '#{attr_value}' has duplicate record"
		else
			if issues.size == 0 || issues == [nil]
				raise NoIssueForUniqueValue, "No issue with #{unique_attr} of '#{attr_value}' found"
			end
			issues.first
		end
	end

	# Returns the id for the given user or raises RecordNotFound
	# Implements a cache of users based on login name
	def user_for_login!(login)
		begin
			if !@user_by_login.has_key?(login)
				@user_by_login[login] = User.find_by_login!(login)
			end
			@user_by_login[login]
		rescue ActiveRecord::RecordNotFound
			@unfound_class = "User"
			@unfound_key = login
			raise
		end
	end

	def user_id_for_login!(login)
		user = user_for_login!(login)
		user ? user.id : nil
	end

	# Returns the id for the given version or raises RecordNotFound.
	# Implements a cache of version ids based on version name
	# If add_versions is true and a valid name is given,
	# will create a new version and save it when it doesn't exist yet.
	def version_id_for_name!(project,name,add_versions)
		if !@version_id_by_name.has_key?(name)
			version = Version.find_by_project_id_and_name(project.id, name)
			if !version
				if name && (name.length > 0) && add_versions
					version = project.versions.build(:name=>name)
					version.save
				else
					@unfound_class = "Version"
					@unfound_key = name
					raise ActiveRecord::RecordNotFound, "No version named #{name}"
				end
			end
			@version_id_by_name[name] = version.id
		end
		@version_id_by_name[name]
	end

	def result
		# Retrieve saved import data
		iip = CsvFileImportInProgress.find_or_create_by(user_id: User.current.id)
		if iip == nil
			flash[:error] = "No import is currently in progress"
			return
		end

		if iip.created.strftime("%Y-%m-%d %H:%M:%S") != params[:import_timestamp]
			flash[:error] = "You seem to have started another import " \
			"since starting this one. " \
			"This import cannot be completed"
			return
		end

		# Detects real encoding and converts as necessary
		latin = latin_encoding(iip.encoding, iip.csv_data)
		if latin[:latin]
			iip.csv_data = latin[:data]
			iip.encoding = latin[:encoding]
		end
		logger.info "[CsvFileImporterController.result] Encoding OK"
		result_errors = []

		# Import
		case iip.import_type
		when 'issue'
			result_errors = import_issues(iip.csv_data, true, iip.encoding, iip.quote_char, iip.col_sep, params)
			render_template = 'issue'
			logger.info "[CsvFileImporterController.result] Issues import in progress..."

		when 'time_entry'
			result_errors = import_time_entries(iip.csv_data, true, iip.encoding, iip.quote_char, iip.col_sep, params)
			render_template = 'time_entry'
			logger.info "[CsvFileImporterController.result] Time entries import in progress..."
		end
		logger.info "[CsvFileImporterController.result] Import OK"

		# Clean up after ourselves
		iip.delete

		# Garbage prevention: clean up iips older than 3 days
		CsvFileImportInProgress.delete_all(["created < ?",Time.new - 3*24*60*60])

		logger.info "[CsvFileImporterController.result] Result errors ##{result_errors.size}"
		if result_errors.size > 0
			logger.info "[CsvFileImporterController.result] Errors : #{result_errors}"
			logger.info "[CsvFileImporterController.result] Redirect to index"
			redirect_to(:action => 'index', :project_id => @project.id)
		else
			logger.info "[CsvFileImporterController.result] Go to result"
			render(:template => "csv_file_importer/result_" + render_template)
		end
	end

	private

	def find_project
		@project = Project.find(params[:project_id])
	end

	def flash_message(type, text)
		flash[type] ||= ""
		flash[type] += "#{text}<br/>"
	end

	def get_settings
		@settings = Setting.plugin_redmine_csv_file_importer
	end

	# Add ISO-8859-1 (or Latin1) and ISO-8859-15 (or Latin9) character encoding support by converting to UTF-8
	def latin_encoding(pencoding, pdata)
		result = nil
		convert = false

		case pencoding
			when 'U'
				csv_data_lat=pdata.force_encoding("utf-8")
			when 'L1'
				csv_data_lat = Iconv.conv("UTF-8", "ISO8859-1", pdata)
				convert = true

			when 'L9'
				csv_data_lat = Iconv.conv("UTF-8", "ISO8859-15", pdata)
				convert = true
		end

		if convert
			result = { :latin => true, :encoding => 'U', :data => csv_data_lat }
		else
			result = { :latin => false }
		end

		return result
	end
  
	def import_issues(csv_data, header, encoding, quote_char, col_sep, params)
		@handle_count = 0
		@update_count = 0
		@skip_count = 0
		@failed_count = 0
		@failed_events = Hash.new
		@failed_messages = Hash.new
		@failed_issues = Hash.new
		@affect_projects_issues = Hash.new
		# This is a cache of previously inserted issues indexed by the value
		# the user provided in the unique column
		@issue_by_unique_attr = Hash.new
		# Cache of user id by login
		@user_by_login = Hash.new
		# Cache of Version by name
		@version_id_by_name = Hash.new

		default_tracker = params[:default_tracker]
		update_issue = params[:update_issue]
		unique_field = params[:unique_field].empty? ? nil : params[:unique_field]
		journal_field = params[:journal_field]
		update_other_project = params[:update_other_project]
		ignore_non_exist = params[:ignore_non_exist]
		fields_map = params[:fields_map]
		send_emails = params[:send_emails]
		add_categories = params[:add_categories]
		add_versions = params[:add_versions]
		unique_attr = fields_map[unique_field]
		unique_attr_checked = false  # Used to optimize some work that has to happen inside the loop   

		# attrs_map is fields_map's invert
		attrs_map = fields_map.invert

		# check params
		errors = []

		if update_issue
			errors << l(:text_rmi_specify_unique_field_for_update)
			errors << "<br>"
		elsif attrs_map["parent_issue"] != nil && unique_field == nil
			errors << l(:text_rmi_specify_unique_field_for_column,:column => l(:field_parent_issue))
			errors << "<br>"
		else
			IssueRelation::TYPES.each_key do |rtype|
				if attrs_map[rtype]
					errors << l(:text_rmi_specify_unique_field_for_column,:column => l("label_#{rtype}".to_sym))
					errors << "<br>"
					break
				end
			end
		end

		if errors.size > 0
			errors.each do |error_message|
				flash_message(:error,"&nbsp;&nbsp;" + error_message)
			end
			# flash[:error] = errors
			return errors
		end

		logger.info "[CsvFileImporterController.import_issues] Début de l'importation des demandes..."

		ActiveRecord::Base.transaction do
			CSV.new(csv_data, {:headers=>header, :encoding=>encoding, 
				:quote_char=>quote_char, :col_sep=>col_sep}).each do |row|

				logger.info "[CsvFileImporterController.import_issues] Définition des attributs"

				project = Project.find_by_name(row[attrs_map["project"]])
				if !project
					project = @project
				end

				begin
					id = row[attrs_map["id"]]
					tracker = Tracker.find_by_name(row[attrs_map["tracker"]])
					status = IssueStatus.find_by_name(row[attrs_map["status"]]) 
					author = row[attrs_map["author"]] != nil ? user_for_login!(row[attrs_map["author"]]) : User.current
					priority = Enumeration.find_by_name(row[attrs_map["priority"]])
					category_name = row[attrs_map["category"]]
					category = IssueCategory.find_by_project_id_and_name(project.id, category_name)
					if (!category) && category_name && category_name.length > 0 && add_categories
						category = project.issue_categories.build(:name => category_name)
						category.save
					end
					assigned_to = row[attrs_map["assigned_to"]] != nil ? user_for_login!(row[attrs_map["assigned_to"]]) : nil
					fixed_version_name = row[attrs_map["fixed_version"]]
					fixed_version_id = fixed_version_name ? version_id_for_name!(project,fixed_version_name,add_versions) : nil
					watchers = row[attrs_map["watchers"]]

					journal = nil

					# new issue or find exists one
					logger.info "[CsvFileImporterController.import_issues] Recherche d'une demande existante"
					issue = Issue.new
					issue.id = id !=  nil ? id : issue.id
					issue.project_id = project != nil ? project.id : @project.id
					issue.tracker_id = tracker != nil ? tracker.id : default_tracker
					issue.author_id = author != nil ? author.id : User.current.id
				rescue ActiveRecord::RecordNotFound
					@failed_count += 1
					@failed_issues[@failed_count] = row
					flash_message(:warning,"When adding issue #{@failed_count} below, the #{@unfound_class} #{@unfound_key} was not found")
					next
				end

			  	

				# translate unique_attr if it's a custom field -- only on the first issue
				logger.info "[CsvFileImporterController.import_issues] Traduction 'unique_attr'"
				if !unique_attr_checked
					if unique_field && !ISSUE_ATTRS.include?(unique_attr.to_sym)
						issue.available_custom_fields.each do |cf|
							if cf.name == unique_attr
								unique_attr = "cf_#{cf.id}"
								break
							end
						end
					end
					unique_attr_checked = true
				end

		      	

				if update_issue
					begin
						logger.info "[CsvFileImporterController.import_issues] update_issue debut"
						issue = issue_for_unique_attr(unique_attr,row[unique_field],row)

						# ignore other project's issue or not
						if issue.project_id != @project.id && !update_other_project
							@skip_count += 1
							next
						end

						# ignore closed issue except reopen
						if issue.status.is_closed?
							if status == nil || status.is_closed?
								@skip_count += 1
								next
							end
						end

						# init journal
						note = row[journal_field] || ''
						journal = issue.init_journal(author || User.current, 
							note || '')

						@update_count += 1

						logger.info "[CsvFileImporterController.import_issues] update_issue fin"

					rescue NoIssueForUniqueValue
						if ignore_non_exist
							@skip_count += 1
							next
						else
							@failed_count += 1
							@failed_issues[@failed_count] = row
							flash_message(:warning,"Could not update issue #{@failed_count} below, no match for the value #{row[unique_field]} were found")
							next
						end

					rescue MultipleIssuesForUniqueValue
						@failed_count += 1
						@failed_issues[@failed_count] = row
						flash_message(:warning,"Could not update issue #{@failed_count} below, multiple matches for the value #{row[unique_field]} were found")
						next
					end
		  		end

				logger.info "[CsvFileImporterController.import_issues] Recuperation des attributs"

				# project affect
				if project == nil
					project = Project.find_by_id(issue.project_id)
				end
				@affect_projects_issues.has_key?(project.name) ?
				@affect_projects_issues[project.name] += 1 : @affect_projects_issues[project.name] = 1

				# required attributes
				issue.status_id = status != nil ? status.id : issue.status_id
				issue.priority_id = priority != nil ? priority.id : issue.priority_id
				issue.subject = row[attrs_map["subject"]] || issue.subject

				# optional attributes
				logger.info "[CsvFileImporterController.import_issues] Optional attributes"
				issue.description = row[attrs_map["description"]] || issue.description
				issue.category_id = category != nil ? category.id : issue.category_id
				issue.start_date = row[attrs_map["start_date"]] || issue.start_date
				issue.due_date = row[attrs_map["due_date"]] || issue.due_date
				issue.assigned_to_id = assigned_to != nil ? assigned_to.id : issue.assigned_to_id
				issue.fixed_version_id = fixed_version_id != nil ? fixed_version_id : issue.fixed_version_id
				issue.done_ratio = row[attrs_map["done_ratio"]] || issue.done_ratio
				issue.estimated_hours = row[attrs_map["estimated_hours"]] || issue.estimated_hours

				# Check that mandatory fields are not empty 
				logger.info "[CsvFileImporterController.import_issues]  Check that mandatory fields are not empty"
				if issue.subject.nil? || issue.subject.blank?             
					@failed_count += 1
					@failed_events[@failed_count] = row
					@failed_messages[@failed_count] = l(:error_mandatory_field_missing)

					logger.info "[CsvFileImporterController.import_issues] failed_count ##{@failed_count}"
					logger.info "[CsvFileImporterController.import_issues] failed : #{row}"

					next
				end

				# parent issues
				logger.info "[CsvFileImporterController.import_issues] Parent issues"
				begin
					parent_value = row[attrs_map["parent_issue"]]
					if parent_value && (parent_value.length > 0)
						issue.parent_issue_id = issue_for_unique_attr(unique_attr,parent_value,row).id
					end
				rescue NoIssueForUniqueValue
					if ignore_non_exist
						@skip_count += 1
					else
						@failed_count += 1
						@failed_issues[@failed_count] = row
						flash_message(:warning,"When setting the parent for issue #{@failed_count} below, no matches for the value #{parent_value} were found")
						next
					end
				rescue MultipleIssuesForUniqueValue
					@failed_count += 1
					@failed_issues[@failed_count] = row
					flash_message(:warning,"When setting the parent for issue #{@failed_count} below, multiple matches for the value #{parent_value} were found")
					next
				end

				# custom fields
				logger.info "[CsvFileImporterController.import_issues] Custom_fields"
				custom_failed_count = 0
				issue.custom_field_values = issue.available_custom_fields.inject({}) do |h, cf|
					if value = row[attrs_map[cf.name]]
						begin
							if cf.field_format == 'user'
								value = user_id_for_login!(value).to_s
							elsif cf.field_format == 'version'
								value = version_id_for_name!(project,value,add_versions).to_s
							elsif cf.field_format == 'date'
								value = value.to_date.to_s(:db)
							end
							h[cf.id] = value
						rescue
							if custom_failed_count == 0
								custom_failed_count += 1
								@failed_count += 1
								@failed_issues[@failed_count] = row
							end
							flash_message(:warning,"When trying to set custom field #{cf.name} on issue #{@failed_count} below, value #{value} was invalid")
						end
					end
					h
				end
				next if custom_failed_count > 0

				# watchers
				logger.info "[CsvFileImporterController.import_issues] Watchers"
				watcher_failed_count = 0
				if watchers
					addable_watcher_users = issue.addable_watcher_users
					watchers.split(',').each do |watcher|
						begin
							watcher_user = user_id_for_login!(watcher)
							if issue.watcher_users.include?(watcher_user)
								next
							end
							if addable_watcher_users.include?(watcher_user)
								issue.add_watcher(watcher_user)
							end
						rescue ActiveRecord::RecordNotFound
							if watcher_failed_count == 0
								@failed_count += 1
								@failed_issues[@failed_count] = row
							end
							watcher_failed_count += 1
							flash_message(:warning,"When trying to add watchers on issue #{@failed_count} below, User #{watcher} was not found")
						end
					end
				end
				next if watcher_failed_count > 0

				# Save
				logger.info "[CsvFileImporterController.import_issues] Save"
				if (!issue.save)
					@failed_count += 1
					@failed_issues[@failed_count] = row
					logger.info "[CsvFileImporterController.import_issues] failed_count ##{@failed_count}"
					logger.info "[CsvFileImporterController.import_issues] failed : #{row}"
					flash_message(:warning,"The following data-validation errors occurred on issue #{@failed_count} in the list below")
					issue.errors.each do |attr, error_message|
						flash_message(:warning,"&nbsp;&nbsp;"+error_message)
						logger.info "[CsvFileImporterController.import_issues] failed error : #{error_message}"
					end
				else
					if unique_field
						@issue_by_unique_attr[row[unique_field]] = issue
					end

					if send_emails
						if update_issue
							if Setting.notified_events.include?('issue_updated') && (!issue.current_journal.empty?)
								Mailer.deliver_issue_edit(issue.current_journal)
							end
						else
							if Setting.notified_events.include?('issue_added')
								Mailer.deliver_issue_add(issue)
							end
						end
					end

					# Issue relations
					begin
						IssueRelation::TYPES.each_pair do |rtype, rinfo|
							if !row[attrs_map[rtype]]
								next
							end
							other_issue = issue_for_unique_attr(unique_attr,row[attrs_map[rtype]],row)
							relations = issue.relations.select { |r| (r.other_issue(issue).id == other_issue.id) && (r.relation_type_for(issue) == rtype) }
							if relations.length == 0
								relation = IssueRelation.new( :issue_from => issue, :issue_to => other_issue, :relation_type => rtype )
								relation.save
							end
						end
					rescue NoIssueForUniqueValue
						if ignore_non_exist
							@skip_count += 1
							next
						end
					rescue MultipleIssuesForUniqueValue
						break
					end

					if journal
						journal
					end

					@handle_count += 1
				end
			end # do
		end # do

		if @failed_events.size > 0
			@failed_events = @failed_events.sort
			@headers = @failed_events[0][1].headers
		end

		if errors.size == 0
			return []
		end
	end

	def import_time_entries(csv_data, header, encoding, quote_char, col_sep, params) 
		@handle_count = 0
		@failed_count = 0
		@failed_events = Hash.new
		@failed_messages = Hash.new

		row_counter = 0
		failed_counter = 0

		fields_map = params[:fields_map]

	    # attrs_map is fields_map's invert
	    attrs_map = fields_map.invert

		# check params
		errors = []

		custom_field = CustomField.find_by_id(@settings['csv_import_issue_id'])
		if attrs_map["issue_id"].nil? && attrs_map[custom_field.name].nil?
			errors << l(:error_issue_field_not_defined )
			errors << "<br>"
		end

		if attrs_map["user_id"].nil?
			errors << l(:error_user_field_not_defined)
			errors << "<br>"
		end

		if attrs_map["spent_on"].nil?
			errors << l(:error_spent_on_field_not_defined)
			errors << "<br>"
		end

		if attrs_map["activity_id"].nil? 
			errors << l(:error_activity_field_not_defined)
			errors << "<br>"
		end

		if attrs_map["hours"].nil? 
			errors << l(:error_hours_field_not_defined)
			errors << "<br>"
		end

		logger.info "[CsvFileImporterController.import_time_entries] Errors ##{errors.size}"
		if errors.size > 0 
			logger.info "[CsvFileImporterController.import_time_entries] Errors : " + errors.to_s
			flash[:error] = errors.join(" ")
			return errors
		end

	    # if update_issue && unique_attr == nil
	    #   flash[:error] = "Unique field hasn't match an issue's field"
	    #   return
	    # end

	    ActiveRecord::Base.transaction do
	    	CSV.new(csv_data, {:headers=>header, :encoding=>encoding, 
	    		:quote_char=>quote_char, :col_sep=>col_sep}).each do |row|

	    		journal = nil

	    		@handle_count += 1
	    		logger.info "[CsvFileImporterController.import_time_entries] Row processed :  #{row}"

			  # Check that mandatory fields are not empty 
			  if (row[attrs_map["issue_id"]].blank? && row[attrs_map[custom_field.name]].blank?) ||
			  	row[attrs_map["hours"]].blank? ||
			  	row[attrs_map["activity_id"]].blank? ||
			  	row[attrs_map["user_id"]].blank? ||
			  	row[attrs_map["spent_on"]].blank?

			  	@failed_count += 1
			  	@failed_events[@failed_count] = row
			  	@failed_messages[@failed_count] = l(:error_mandatory_field_missing)

			  	logger.info "[CsvFileImporterController.import_time_entries] failed_count ##{@failed_count}"
			  	logger.info "[CsvFileImporterController.import_time_entries] failed : #{row}"

			  	next
			  end

			  logger.info "[CsvFileImporterController.import_time_entries] success : #{row}"
			  project = Project.find_by_name(row[attrs_map["project"]])

			  logger.info "[CsvFileImporterController.import_time_entries] project : #{project}"

			  begin
			  	if row[attrs_map["issue_id"]].nil?
			        # find issue from custom field
			        custom_field = CustomField.find_by_id(@settings['csv_import_issue_id'])
			        custom_field_value = CustomValue.where(:custom_field_id => custom_field.id, 
			        	:value => row[attrs_map[custom_field.name]]).first
			        issue_id = Issue.find_by_id(custom_field_value.customized_id)
			        issue_id = issue_id.id
			    else
			    	issue_id = Issue.find_by_id(row[attrs_map["issue_id"]])
			    	issue_id = issue_id.id
			    end
			rescue NilClass::NoMethodError => ex
				@failed_count += 1
				@failed_events[@failed_count] = row
				@failed_messages[@failed_count] = l(:error_issue_id_not_existing) + " (#{ex.message[0..49]}...)"
				logger.info "[CsvFileImporterController.import_time_entries] failed_count ##{@failed_count}"
				logger.info "[CsvFileImporterController.import_time_entries] failed : #{row}"
				logger.info "[CsvFileImporterController.import_time_entries] failed error : #{ex}"
				next
			end

			  # new time entry
			  time = TimeEntry.new

			  time.project_id = project != nil ? project.id : @project.id
			  time.issue_id = issue_id
			  #time.issue_id = Issue.find_by_name ...
			  TimeEntryActivity.find_by_name(row[attrs_map["activity_id"]].strip)
			  time.spent_on = row[attrs_map["spent_on"]]
		      #time.activity = activity_id
		      time.activity = TimeEntryActivity.find_by_name(row[attrs_map["activity_id"]].strip)
		      time.hours = row[attrs_map["hours"]]
		      
		      # Truncate comments to 255 chars
		      time.comments = row[attrs_map["comments"]].mb_chars[0..255].strip.to_s if row[attrs_map["comments"]].present?
		      time.user = User.find_by_login(row[attrs_map["user_id"]].strip)

			  # Just for log
			  t_s = ""
			  time.attributes.sort.each do | a_n, a_v |
			  	t_s += "#{a_n} : #{a_v} | "
			  end

			  logger.info "[CsvFileImporterController.import_time_entries] TimeEntry : #{t_s}"

			  begin
			  	time.save!
			  rescue ActiveRecord::StatementInvalid, ActiveRecord::RecordNotSaved, ActiveRecord::RecordInvalid => ex
			  	@failed_count += 1
			  	@failed_events[@failed_count] = row
			  	@failed_messages[@failed_count] = l(:error_time_entry_not_saved) + " (#{ex.message[0..49]}...)"
			  	logger.info "[CsvFileImporterController.import_time_entries] failed_count ##{@failed_count}"
			  	logger.info "[CsvFileImporterController.import_time_entries] failed : #{row}"
			  	logger.info "[CsvFileImporterController.import_time_entries] failed error : #{ex}"
			  	next
			  end
			end
		end

		if @failed_events.size > 0
			@failed_events = @failed_events.sort
			@headers = @failed_events[0][1].headers
			logger.info "[CsvFileImporterController.import_time_entries] Failed summary : #{@failed_events}"
		end

		if errors.size == 0
			return []
		end
	end
end
