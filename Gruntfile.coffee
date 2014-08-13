DIST_DIR = 'static/dist'
BOWER_COMPONENTS = 'static/components'

CSS_MERGED = "#{DIST_DIR}/merged.css"


module.exports = (grunt) ->
  # Project configuration.
  #
  css_combine_files = {}
  css_combine_files[CSS_MERGED] = [
    "#{BOWER_COMPONENTS}/bootstrap/dist/css/bootstrap.css",
    "#{BOWER_COMPONENTS}/github-fork-ribbon-css/gh-fork-ribbon.css",
    "#{BOWER_COMPONENTS}/bootstrap-tagsinput/dist/bootstrap-tagsinput.css",
    'static/disturbe.css']

  grunt.initConfig
    pkg: grunt.file.readJSON('package.json')
    coffee:
      compile:
        files:
          'static/dist/disturbe.js': 'static/disturbe.coffee'
    copy:
      fontAwesome:
        files: [
          expand: true
          cwd: 'static/components/'
          src: ['font-awesome/**']
          dest: DIST_DIR
          ]
      requirejs:
        files: [
          expand: true
          cwd: 'static/components/requirejs/'
          src: ['require.js']
          dest: "#{DIST_DIR}/"
          ]
    cssmin:
      combine:
        keepSpecialComments: 0
        files: css_combine_files
      minify:
        expand: true
        cwd: DIST_DIR
        src: ['*.css', '!*.min.css']
        dest: DIST_DIR
        ext: '.min.css'
    requirejs:
      compile:
        options:
          mainConfigFile : "static/disturbe.js"
          baseUrl : "static"
          name: "disturbe"
          out: "#{DIST_DIR}/merged.min.js"
          removeCombined: true
          findNestedDependencies: true

  # Load the plugin that provides the "uglify" task.
  grunt.loadNpmTasks 'grunt-contrib-coffee'
  grunt.loadNpmTasks 'grunt-contrib-copy'
  grunt.loadNpmTasks 'grunt-contrib-cssmin'
  grunt.loadNpmTasks 'grunt-requirejs'

  # Default task(s).
  # grunt.registerTask('default', ['coffee']);
  grunt.registerTask 'default', [
    'coffee', 'requirejs', 'cssmin:combine', 'cssmin:minify',
    'copy:requirejs', 'copy:fontAwesome']
