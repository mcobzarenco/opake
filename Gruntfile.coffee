DIST_DIR = 'dist'
BOWER_COMPONENTS = 'bower_components'

CSS_MERGED = "#{DIST_DIR}/merged.css"
CONCATENATED_JS = "#{DIST_DIR}/merged.js"
UGLYFIED_JS = "#{DIST_DIR}/merged.min.js"

module.exports = (grunt) ->
  # Project configuration.
  #
  cssCombineFiles = {}
  cssCombineFiles[CSS_MERGED] = [
    "#{BOWER_COMPONENTS}/bootstrap/dist/css/bootstrap.css",
    "#{BOWER_COMPONENTS}/github-fork-ribbon-css/gh-fork-ribbon.css",
    "#{BOWER_COMPONENTS}/bootstrap-tagsinput/dist/bootstrap-tagsinput.css",
    'src/app.css']

  uglifyFiles = {}
  uglifyFiles[UGLYFIED_JS] = CONCATENATED_JS

  filesStringReplace = {}
  filesStringReplace["#{BOWER_COMPONENTS}/nprogress/nprogress.css"] = "#{BOWER_COMPONENTS}/nprogress/nprogress.css"

  grunt.initConfig
    pkg: grunt.file.readJSON('package.json')
    coffee:
      compile:
        files:
          'src/app.js': 'src/app.coffee'
    copy:
      fontAwesome:
        files: [
          expand: true
          cwd: BOWER_COMPONENTS
          src: ['font-awesome/**']
          dest: DIST_DIR
          ]
      requirejs:
        files: [
          expand: true
          cwd: "#{BOWER_COMPONENTS}/requirejs"
          src: ['require.js']
          dest: "#{DIST_DIR}/"
          ]
    cssmin:
      combine:
        keepSpecialComments: 0
        files: cssCombineFiles
      minify:
        expand: true
        cwd: DIST_DIR
        src: ['*.css', '!*.min.css']
        dest: DIST_DIR
        ext: '.min.css'
    requirejs:
      compile:
        options:
          mainConfigFile : "src/app.js"

          name: "app"
          out: "#{DIST_DIR}/merged.js"
          optimize: 'none'
          # removeCombined: false
          # findNestedDependencies: true
          uglify:
            compress: false
            toplevel: true,
            ascii_only: true,
            beautify: true,
            max_line_length: 1000,

            # How to pass uglifyjs defined symbols for AST symbol replacement,
            # see "defines" options for ast_mangle in the uglifys docs.
            defines: {
                DEBUG: ['name', 'false']
            },
            # in uglifyjs directly:
            # Skip the processor.ast_mangle() part of the uglify call (r.js 2.0.5+)
            no_mangle: true
    'string-replace':
      dist:
        files: filesStringReplace
        options:
          replacements: [{
            pattern: /29d/g
            replacement: '859900'
          }]
    uglify:
      main:
        options:
          compress: false
          mangle: true
        files: uglifyFiles


  # Load the plugin that provides the "uglify" task.
  grunt.loadNpmTasks 'grunt-contrib-coffee'
  grunt.loadNpmTasks 'grunt-contrib-copy'
  grunt.loadNpmTasks 'grunt-contrib-cssmin'
  grunt.loadNpmTasks 'grunt-contrib-uglify'
  grunt.loadNpmTasks 'grunt-contrib-requirejs'
  grunt.loadNpmTasks 'grunt-string-replace'

  # Default task(s).
  grunt.registerTask 'default', [ 'coffee', 'string-replace',
    'requirejs', 'uglify', 'cssmin:combine', 'cssmin:minify',
    'copy:requirejs', 'copy:fontAwesome']
